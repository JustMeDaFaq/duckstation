#include "cheevos.h"
#include "common/file_system.h"
#include "common/log.h"
#include "common/string.h"
#include "common/string_util.h"
#include "common_host_interface.h"
#include "core/bus.h"
#include "core/cpu_core.h"
#include "core/host_display.h"
#include "core/system.h"
#include "fullscreen_ui.h"
#include "rapidjson/document.h"
#include "rc_consoles.h"
#include "rc_hash.h"
#include "rc_url.h"
#include "rcheevos.h"
#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <functional>
#include <string>
#include <vector>
Log_SetChannel(Cheevos);

#ifdef _WIN32
#include "common/windows_headers.h"
#include <WinInet.h>
#pragma comment(lib, "wininet.lib")
#endif

enum : s32
{
  HTTP_OK = 200
};

struct HTTPRequest
{
  using Data = std::vector<u8>;
  using Callback = std::function<void(s32 status_code, const Data& data)>;

  enum class State
  {
    Pending,
    Cancelled,
    Started,
    Receiving,
    Complete,
  };

  Callback callback;
  std::string url;
  Data data;
  Common::Timer timeout;
  s32 status_code = 0;
  u32 content_length = 0;
  std::atomic<State> state{State::Pending};

#ifdef _WIN32
  HINTERNET hUrl = NULL;
  bool io_pending = false;
  u32 io_position = 0;
#endif
};

static bool InitializeHTTP();
static void ShutdownHTTP();
static u32 GetActiveHTTPRequestCount();
static void CreateHTTPRequest(const char* url, HTTPRequest::Callback callback);
static bool StartHTTPRequest(HTTPRequest* req);
static void WaitForHTTPResponse();
static void PollForHTTPResponse();

static constexpr char USER_AGENT[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0";
static constexpr float HTTP_TIMEOUT_IN_SECONDS = 10;
static constexpr u32 HTTP_MAX_ACTIVE_REQUESTS = 4;

#ifdef _WIN32
static HINTERNET s_hInternet;
static std::mutex s_pending_http_request_lock;
static std::vector<HTTPRequest*> s_pending_http_requests;

static void CALLBACK HTTPStatusCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
                                        LPVOID lpvStatusInformation, DWORD dwStatusInformationLength)
{
  HTTPRequest* req = reinterpret_cast<HTTPRequest*>(dwContext);
  if (dwInternetStatus == INTERNET_STATUS_HANDLE_CREATED)
  {
    req->hUrl = reinterpret_cast<HINTERNET>(reinterpret_cast<INTERNET_ASYNC_RESULT*>(lpvStatusInformation)->dwResult);
    return;
  }
  else if (dwInternetStatus == INTERNET_STATUS_HANDLE_CLOSING)
  {
    std::unique_lock<std::mutex> lock(s_pending_http_request_lock);
    Assert(std::none_of(s_pending_http_requests.begin(), s_pending_http_requests.end(),
                        [req](HTTPRequest* it) { return it == req; }));
    delete req;
    return;
  }
  else if (dwInternetStatus != INTERNET_STATUS_REQUEST_COMPLETE)
  {
    return;
  }

  Log_DevPrintf("Request '%s' complete callback", req->url.c_str());
  Assert(req->hUrl != NULL && req->state != HTTPRequest::State::Complete);

  if (req->state == HTTPRequest::State::Started)
  {
    DWORD buffer_length = sizeof(req->status_code);
    DWORD next_index = 0;
    HttpQueryInfoA(req->hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &req->status_code, &buffer_length,
                   &next_index);

    if (req->status_code == HTTP_OK)
    {
      req->state = HTTPRequest::State::Receiving;

      // try for content-length, but it might not exist
      DWORD buffer_length = sizeof(req->content_length);
      DWORD next_index = 0;
      HttpQueryInfoA(req->hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &req->content_length,
                     &buffer_length, &next_index);
      if (req->content_length > 0)
        req->data.reserve(req->content_length);
    }
  }

  if (req->state == HTTPRequest::State::Receiving)
  {
    // this is a completed I/O - get the number of bytes written and resize the buffer accordingly
    if (req->io_pending)
    {
      if (!static_cast<BOOL>(reinterpret_cast<INTERNET_ASYNC_RESULT*>(lpvStatusInformation)->dwResult))
      {
        const DWORD error = reinterpret_cast<INTERNET_ASYNC_RESULT*>(lpvStatusInformation)->dwError;
        Log_ErrorPrintf("Async InternetReadFile() returned %u", error);
        req->data.clear();
        req->status_code = -1;
        req->state.store(HTTPRequest::State::Complete);
        return;
      }

      req->io_pending = false;
    }

    // we need to call InternetReadFile until it returns TRUE and writes zero bytes.
    for (;;)
    {
      const u32 bytes_to_read = (req->content_length > 0) ? (req->content_length - static_cast<u32>(req->data.size())) :
                                                            std::max<u32>(128, static_cast<u32>(req->data.size()));
      if (bytes_to_read == 0)
      {
        req->state.store(HTTPRequest::State::Complete);
        break;
      }

      req->io_position = static_cast<u32>(req->data.size());
      req->data.resize(req->io_position + bytes_to_read);

      DWORD bytes_read = 0;
      if (InternetReadFile(req->hUrl, &req->data[req->io_position], bytes_to_read, &bytes_read))
      {
        if (bytes_read == 0)
        {
          // end of buffer
          req->data.resize(req->io_position);
          req->state.store(HTTPRequest::State::Complete);
          break;
        }

        req->data.resize(req->io_position + bytes_read);
      }
      else
      {
        if (GetLastError() == ERROR_IO_PENDING)
        {
          req->io_pending = true;
          return;
        }

        Log_ErrorPrintf("InternetReadFile() error: %u", GetLastError());
        req->status_code = -1;
        req->data.clear();
        req->state.store(HTTPRequest::State::Complete);
        break;
      }
    }
  }
}

bool InitializeHTTP()
{
  s_hInternet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, INTERNET_FLAG_ASYNC);
  if (s_hInternet == NULL)
    return false;

  InternetSetStatusCallback(s_hInternet, HTTPStatusCallback);
  return true;
}

void ShutdownHTTP()
{
  if (s_hInternet)
  {
    InternetCloseHandle(s_hInternet);
    s_hInternet = NULL;
  }
}

u32 GetActiveHTTPRequestCount()
{
  u32 count = 0;
  for (HTTPRequest* req : s_pending_http_requests)
  {
    if (req->state == HTTPRequest::State::Started || req->state == HTTPRequest::State::Receiving)
      count++;
  }
  return count;
}

void CreateHTTPRequest(std::string url, HTTPRequest::Callback callback)
{
  HTTPRequest* req = new HTTPRequest();
  req->url = std::move(url);
  req->callback = std::move(callback);

  std::unique_lock<std::mutex> lock(s_pending_http_request_lock);
  if (GetActiveHTTPRequestCount() < HTTP_MAX_ACTIVE_REQUESTS)
  {
    if (!StartHTTPRequest(req))
      return;
  }

  s_pending_http_requests.push_back(std::move(req));
}

bool StartHTTPRequest(HTTPRequest* req)
{
  req->hUrl = InternetOpenUrlA(s_hInternet, req->url.c_str(), nullptr, 0, INTERNET_FLAG_ASYNC | INTERNET_FLAG_NO_UI,
                               reinterpret_cast<DWORD_PTR>(req));
  if (req->hUrl != NULL || GetLastError() == ERROR_IO_PENDING)
  {
    Log_DevPrintf("Started HTTP request for '%s'", req->url.c_str());
    req->state = HTTPRequest::State::Started;
    req->timeout.Reset();
    return true;
  }

  Log_ErrorPrintf("Failed to start HTTP request for '%s': %u", req->url.c_str(), GetLastError());
  req->callback(-1, req->data);
  delete req;
  return false;
}

static void PollForHTTPResponse(std::unique_lock<std::mutex>& lock)
{
  u32 active_requests = 0;
  u32 unstarted_requests = 0;
  for (size_t index = 0; index < s_pending_http_requests.size();)
  {
    HTTPRequest* req = s_pending_http_requests[index];
    if (req->state == HTTPRequest::State::Pending)
    {
      unstarted_requests++;
      index++;
      continue;
    }

    if (req->state == HTTPRequest::State::Started && req->timeout.GetTimeSeconds() >= HTTP_TIMEOUT_IN_SECONDS)
    {
      // request timed out
      Log_ErrorPrintf("Request for '%s' timed out", req->url.c_str());
      req->state.store(HTTPRequest::State::Cancelled);
      req->callback(-1, HTTPRequest::Data());

      if (req->hUrl != NULL)
      {
        // req will be freed by the callback
        InternetCloseHandle(req->hUrl);
        req->hUrl = NULL;
      }
      else
      {
        delete req;
      }

      s_pending_http_requests.erase(s_pending_http_requests.begin() + index);
      continue;
    }

    if (req->state != HTTPRequest::State::Complete)
    {
      active_requests++;
      index++;
      continue;
    }

    // request complete
    Log_DevPrintf("Request for '%s' complete, returned status code %u and %zu bytes", req->url.c_str(),
                  req->status_code, req->data.size());
    s_pending_http_requests.erase(s_pending_http_requests.begin() + index);

    // run callback with lock unheld
    lock.unlock();
    req->callback(req->status_code, req->data);

    // close the handle, the status callback will free the memory
    if (req->hUrl != NULL)
      InternetCloseHandle(req->hUrl);
    else
      delete req;

    lock.lock();
  }

  // start new requests when we finished some
  if (unstarted_requests > 0 && active_requests < HTTP_MAX_ACTIVE_REQUESTS)
  {
    for (size_t index = 0; index < s_pending_http_requests.size();)
    {
      HTTPRequest* req = s_pending_http_requests[index];
      if (req->state != HTTPRequest::State::Pending)
      {
        index++;
        continue;
      }

      if (!StartHTTPRequest(req))
      {
        s_pending_http_requests.erase(s_pending_http_requests.begin() + index);
        continue;
      }

      active_requests++;
      index++;

      if (active_requests >= HTTP_MAX_ACTIVE_REQUESTS)
        break;
    }
  }
}

void WaitForHTTPResponse()
{
  std::unique_lock<std::mutex> lock(s_pending_http_request_lock);
  while (!s_pending_http_requests.empty())
    PollForHTTPResponse(lock);
}

void PollForHTTPResponse()
{
  std::unique_lock<std::mutex> lock(s_pending_http_request_lock);
  PollForHTTPResponse(lock);
}

#else

#endif

namespace Cheevos {

static void CheevosEventHandler(const rc_runtime_event_t* runtime_event);
static unsigned CheevosPeek(unsigned address, unsigned num_bytes, void* ud);

bool g_active = false;

static bool s_logged_in = false;
static CommonHostInterface* s_host_interface;
static rc_runtime_t s_rcheevos_runtime;
static std::string s_username;
static std::string s_login_token;
static s32 s_score;
static u32 s_game_id = 0;
static std::string s_game_title;
static std::string s_game_developer;
static std::string s_game_publisher;
static std::string s_game_release_date;
static std::string s_game_icon;
static std::vector<Achievement> s_achievements;

static void FormattedError(const char* format, ...)
{
  if (!s_host_interface)
    return;

  std::va_list ap;
  va_start(ap, format);

  SmallString str;
  str.AppendString("Cheevos Error: ");
  str.AppendFormattedStringVA(format, ap);

  va_end(ap);

  s_host_interface->AddOSDMessage(str.GetCharArray(), 10.0f);
}

static bool ParseResponseJSON(const char* request_type, s32 status_code, const HTTPRequest::Data& data,
                              rapidjson::Document& doc, const char* success_field = "Success")
{
  if (status_code != HTTP_OK || data.empty())
  {
    FormattedError("%s failed: empty response", request_type);
    return false;
  }

  doc.Parse(reinterpret_cast<const char*>(data.data()), data.size());
  if (doc.HasParseError())
  {
    FormattedError("%s failed: parse error at offset %zu: %u", request_type, doc.GetErrorOffset(),
                   static_cast<unsigned>(doc.GetParseError()));
    return false;
  }

  if (success_field && (!doc.HasMember(success_field) || !doc[success_field].GetBool()))
  {
    FormattedError("%s failed: Server returned an error", request_type);
    return false;
  }

  return true;
}

template<typename T>
static std::string GetOptionalString(const T& value, const char* key)
{
  if (!value.HasMember(key) || !value[key].IsString())
    return std::string();

  return value[key].GetString();
}

template<typename T>
static u32 GetOptionalUInt(const T& value, const char* key)
{
  if (!value.HasMember(key) || !value[key].IsUint())
    return 0;

  return value[key].GetUint();
}

static Achievement* GetAchievementByID(u32 id)
{
  for (Achievement& ach : s_achievements)
  {
    if (ach.id == id)
      return &ach;
  }

  return nullptr;
}

static void ClearAchievements()
{
  while (!s_achievements.empty())
  {
    Achievement& ach = s_achievements.back();
    rc_runtime_deactivate_achievement(&s_rcheevos_runtime, ach.id);
    s_achievements.pop_back();
  }
}

static void ClearGameInfo()
{
  ClearAchievements();
  std::string().swap(s_game_title);
  std::string().swap(s_game_developer);
  std::string().swap(s_game_publisher);
  std::string().swap(s_game_icon);
  s_game_id = 0;
}

bool Initialize(CommonHostInterface* hi)
{
  if (!InitializeHTTP())
    return false;

  s_host_interface = hi;
  g_active = true;
  rc_runtime_init(&s_rcheevos_runtime);
  return true;
}

void Shutdown()
{
  if (!g_active)
    return;

  if (s_logged_in)
  {
    LogoutAsync();
    WaitForHTTPResponse();
  }

  s_host_interface = nullptr;
  g_active = false;
  rc_runtime_destroy(&s_rcheevos_runtime);

  ShutdownHTTP();
}

bool HasActiveGame()
{
  return (s_game_id != 0);
}

void Update()
{
  PollForHTTPResponse();

  if (HasActiveGame())
    rc_runtime_do_frame(&s_rcheevos_runtime, &CheevosEventHandler, &CheevosPeek, nullptr, nullptr);
}

static void LoginASyncCallback(void* context, s32 status_code, const HTTPRequest::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Login", status_code, data, doc, nullptr))
    return;

  if (!doc["Success"].IsBool() || !doc["Success"].GetBool() || !doc["User"].IsString() || !doc["Token"].IsString())
  {
    FormattedError("Login failed. Please check your user name and password, and try again.");
    return;
  }

  s_username = doc["User"].GetString();
  s_login_token = doc["Token"].GetString();
  s_score = doc["Score"].GetInt();
  s_logged_in = true;

  s_host_interface->AddFormattedOSDMessage(5.0f, "Logged into cheevos using username '%s'. You have %d points.",
                                           s_username.c_str(), s_score);

  // If we have a game running, set it up.
  if (System::IsValid())
    GameChanged();
}

bool LoginAsync(const char* username, const char* password)
{
  WaitForHTTPResponse();
  if (s_logged_in)
    return false;

#if 0
  char url[256] = {};
  int res = rc_url_login_with_password(url, sizeof(url), username, password);
  Assert(res == 0);

  return CreateHTTPRequest(url, LoginASyncCallback, nullptr);
#elif 1
  static const char ddata[] =
    "";
  std::vector<u8> vdata;
  for (char ch : ddata)
    vdata.push_back((u8)ch);
  LoginASyncCallback(nullptr, 200, std::move(vdata));
  return true;
#else
  s_username = "";
  s_login_token = "";
  s_logged_in = true;
#endif
}

void LogoutAsync()
{
  //
}

static void DownloadImage(std::string url, std::string cache_filename)
{
  auto callback = [cache_filename](s32 status_code, const HTTPRequest::Data& data) {
    if (status_code != HTTP_OK)
      return;

    if (!FileSystem::WriteBinaryFile(cache_filename.c_str(), data.data(), data.size()))
    {
      Log_ErrorPrintf("Failed to write badge image to '%s'", cache_filename.c_str());
      return;
    }

    FullscreenUI::InvalidateCachedTexture(cache_filename);
  };

  CreateHTTPRequest(std::move(url), std::move(callback));
}

static std::string GetBadgeImageFilename(const char* badge_name, bool locked, bool cache_path)
{
  if (!cache_path)
  {
    return StringUtil::StdStringFromFormat("%s%s.png", badge_name, locked ? "_lock" : "");
  }
  else
  {
    // well, this comes from the internet.... :)
    SmallString clean_name(badge_name);
    FileSystem::SanitizeFileName(clean_name);
    return s_host_interface->GetUserDirectoryRelativePath("cache" FS_OSPATH_SEPARATOR_STR
                                                          "achievement_badge" FS_OSPATH_SEPARATOR_STR "%s%s.png",
                                                          clean_name.GetCharArray(), locked ? "_lock" : "");
  }
}

static std::string ResolveBadgePath(const char* badge_name, bool locked)
{
  char url[256];

  // unlocked image
  std::string cache_path(GetBadgeImageFilename(badge_name, locked, true));
  if (FileSystem::FileExists(cache_path.c_str()))
    return cache_path;

  std::string badge_name_with_extension(GetBadgeImageFilename(badge_name, locked, false));
  int res = rc_url_get_badge_image(url, sizeof(url), badge_name_with_extension.c_str());
  Assert(res == 0);
  DownloadImage(url, std::move(cache_path));
  return cache_path;
}

static void GetPatchesCallback(void* context, s32 status_code, const HTTPRequest::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Get Patches", status_code, data, doc))
    return;

  if (!doc.HasMember("PatchData"))
  {
    FormattedError("No patch data returned from server.");
    return;
  }

  // parse info
  const auto patch_data(doc["PatchData"].GetObject());
  s_game_title = GetOptionalString(patch_data, "Title");
  s_game_developer = GetOptionalString(patch_data, "Developer");
  s_game_publisher = GetOptionalString(patch_data, "Publisher");
  s_game_release_date = GetOptionalString(patch_data, "Released");

  // parse achievements
  if (patch_data.HasMember("Achievements") && patch_data["Achievements"].IsArray())
  {
    const auto achievements(patch_data["Achievements"].GetArray());
    for (const auto& achievement : achievements)
    {
      if (!achievement.HasMember("ID") || !achievement["ID"].IsNumber() || !achievement.HasMember("MemAddr") ||
          !achievement["MemAddr"].IsString() || !achievement.HasMember("Title") || !achievement["Title"].IsString())
      {
        continue;
      }

      const u32 id = achievement["ID"].GetUint();
      const char* memaddr = achievement["MemAddr"].GetString();
      std::string title = achievement["Title"].GetString();
      std::string description = GetOptionalString(achievement, "Description");
      std::string badge_name = GetOptionalString(achievement, "BadgeName");
      const u32 points = GetOptionalUInt(achievement, "Points");
      const bool locked = true;

      if (GetAchievementByID(id))
      {
        Log_ErrorPrintf("Achievement %u already exists", id);
        continue;
      }

      if (locked)
      {
        const int err = rc_runtime_activate_achievement(&s_rcheevos_runtime, id, memaddr, nullptr, 0);
        if (err != RC_OK)
        {
          Log_ErrorPrintf("Achievement %u memaddr parse error: %s", id, rc_error_str(err));
          continue;
        }
      }

      Achievement achievement;
      achievement.id = id;
      achievement.title = std::move(title);
      achievement.description = std::move(description);
      achievement.locked = locked;
      achievement.points = points;

      if (!badge_name.empty())
      {
        achievement.locked_badge_path = ResolveBadgePath(badge_name.c_str(), true);
        achievement.unlocked_badge_path = ResolveBadgePath(badge_name.c_str(), false);
      }

      s_achievements.push_back(std::move(achievement));
    }
  }

  // try for a icon
  std::string icon_name(GetOptionalString(patch_data, "ImageIcon"));
  if (!icon_name.empty())
  {
    s_game_icon = s_host_interface->GetUserDirectoryRelativePath(
      "cache" FS_OSPATH_SEPARATOR_STR "achievement_gameicon" FS_OSPATH_SEPARATOR_STR "%u.png", s_game_id);
    if (!FileSystem::FileExists(s_game_icon.c_str()))
    {
      // for some reason rurl doesn't have this :(
      std::string icon_url(StringUtil::StdStringFromFormat("http://i.retroachievements.org%s", icon_name.c_str()));
      DownloadImage(std::move(icon_url), s_game_icon);
    }
  }

  Log_InfoPrintf("Game Title: %s", s_game_title.c_str());
  Log_InfoPrintf("Game Developer: %s", s_game_developer.c_str());
  Log_InfoPrintf("Game Publisher: %s", s_game_publisher.c_str());
  Log_InfoPrintf("Achievements: %u", s_achievements.size());

  s_host_interface->AddFormattedOSDMessage(5.0f, "Loaded %zu achievements for %s.", s_achievements.size(),
                                           s_game_title.c_str());
}

static void GetPatches()
{
#if 0
  char url[256] = {};
  int res = rc_url_get_patch(url, sizeof(url), s_username.c_str(), s_login_token.c_str(), s_game_id);
  Assert(res == 0);

  if (!SendHTTPRequest(url, GetPatchesCallback, nullptr))
    FormattedError("Failed to send HTTP request for patches.");
#else
  std::optional<std::vector<u8>> f = FileSystem::ReadBinaryFile("D:\\10434.txt");
  if (!f)
    return;

  GetPatchesCallback(nullptr, 200, *f);
#endif
}

static void GetGameIdCallback(void* context, s32 status_code, const HTTPRequest::Data& data)
{
  //
}

void GameChanged()
{
#if 0
#else
  s_game_id = 10434;
  GetPatches();
#endif
}

const std::string& GetGameTitle()
{
  return s_game_title;
}

const std::string& GetGameDeveloper()
{
  return s_game_developer;
}

const std::string& GetGamePublisher()
{
  return s_game_publisher;
}

const std::string& GetGameReleaseDate()
{
  return s_game_release_date;
}

const std::string& GetGameIcon()
{
  return s_game_icon;
}

bool EnumerateAchievements(std::function<bool(const Achievement&)> callback)
{
  for (const Achievement& cheevo : s_achievements)
  {
    if (!callback(cheevo))
      return false;
  }

  return true;
}

u32 GetUnlockedAchiementCount()
{
  u32 count = 0;
  for (const Achievement& cheevo : s_achievements)
  {
    if (!cheevo.locked)
      count++;
  }

  return count;
}

u32 GetAchievementCount()
{
  return static_cast<u32>(s_achievements.size());
}

u32 GetMaximumPointsForGame()
{
  u32 points = 0;
  for (const Achievement& cheevo : s_achievements)
    points += cheevo.points;

  return points;
}

u32 GetCurrentPointsForGame()
{
  u32 points = 0;
  for (const Achievement& cheevo : s_achievements)
  {
    if (!cheevo.locked)
      points += cheevo.points;
  }

  return points;
}

void CheevosEventHandler(const rc_runtime_event_t* runtime_event)
{
  static const char* events[] = {"RC_RUNTIME_EVENT_ACHIEVEMENT_ACTIVATED", "RC_RUNTIME_EVENT_ACHIEVEMENT_PAUSED",
                                 "RC_RUNTIME_EVENT_ACHIEVEMENT_RESET",     "RC_RUNTIME_EVENT_ACHIEVEMENT_TRIGGERED",
                                 "RC_RUNTIME_EVENT_ACHIEVEMENT_PRIMED",    "RC_RUNTIME_EVENT_LBOARD_STARTED",
                                 "RC_RUNTIME_EVENT_LBOARD_CANCELED",       "RC_RUNTIME_EVENT_LBOARD_UPDATED",
                                 "RC_RUNTIME_EVENT_LBOARD_TRIGGERED",      "RC_RUNTIME_EVENT_ACHIEVEMENT_DISABLED",
                                 "RC_RUNTIME_EVENT_LBOARD_DISABLED"};
  const char* event_text =
    ((unsigned)runtime_event->type >= countof(events)) ? "unknown" : events[(unsigned)runtime_event->type];
  Log_InfoPrintf("Cheevos Event %s for %u", event_text, runtime_event->id);

  if (runtime_event->type == RC_RUNTIME_EVENT_ACHIEVEMENT_TRIGGERED)
  {
    Achievement* achievement = GetAchievementByID(runtime_event->id);
    if (achievement)
    {
      // TODO: Remove memref?
      achievement->locked = false;

      FullscreenUI::AddNotification(FullscreenUI::NotificationType::AchievementUnlocked, 15.0f, "Achievement Unlocked!",
                                    achievement->title, achievement->unlocked_badge_path);
    }
  }
}

// from cheats.cpp - do we want to move this somewhere else?
template<typename T>
static T DoMemoryRead(PhysicalMemoryAddress address)
{
  T result;

  if ((address & CPU::DCACHE_LOCATION_MASK) == CPU::DCACHE_LOCATION &&
      (address & CPU::DCACHE_OFFSET_MASK) < CPU::DCACHE_SIZE)
  {
    std::memcpy(&result, &CPU::g_state.dcache[address & CPU::DCACHE_OFFSET_MASK], sizeof(result));
    return result;
  }

  address &= CPU::PHYSICAL_MEMORY_ADDRESS_MASK;

  if (address < Bus::RAM_MIRROR_END)
  {
    std::memcpy(&result, &Bus::g_ram[address & Bus::RAM_MASK], sizeof(result));
    return result;
  }

  if (address >= Bus::BIOS_BASE && address < (Bus::BIOS_BASE + Bus::BIOS_SIZE))
  {
    std::memcpy(&result, &Bus::g_bios[address & Bus::BIOS_MASK], sizeof(result));
    return result;
  }

  result = static_cast<T>(0);
  return result;
}

unsigned CheevosPeek(unsigned address, unsigned num_bytes, void* ud)
{
  switch (num_bytes)
  {
    case 1:
      return ZeroExtend32(DoMemoryRead<u8>(address));
    case 2:
      return ZeroExtend32(DoMemoryRead<u16>(address));
    case 4:
      return ZeroExtend32(DoMemoryRead<u32>(address));
    default:
      return 0;
  }
}

} // namespace Cheevos