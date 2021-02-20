#pragma once
#include "core/types.h"
#include <functional>
#include <string>

class CommonHostInterface;

namespace Cheevos {

struct Achievement
{
  u32 id;
  std::string title;
  std::string description;
  std::string locked_badge_path;
  std::string unlocked_badge_path;
  u32 points;
  bool locked;
};

extern bool g_active;
ALWAYS_INLINE bool IsActive()
{
  return g_active;
}

bool Initialize(CommonHostInterface* hi);
void Shutdown();
void Update();

bool IsLoggedIn();
bool LoginAsync(const char* username, const char* password);
void LogoutAsync();

bool HasActiveGame();
void GameChanged();

const std::string& GetGameTitle();
const std::string& GetGameDeveloper();
const std::string& GetGamePublisher();
const std::string& GetGameReleaseDate();
const std::string& GetGameIcon();

bool EnumerateAchievements(std::function<bool(const Achievement&)> callback);
u32 GetUnlockedAchiementCount();
u32 GetAchievementCount();
u32 GetMaximumPointsForGame();
u32 GetCurrentPointsForGame();

} // namespace Cheevos
