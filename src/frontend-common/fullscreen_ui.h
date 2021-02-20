#pragma once
#include "common/types.h"
#include <string>

class CommonHostInterface;
class SettingsInterface;
struct Settings;

namespace FrontendCommon {
enum class ControllerNavigationButton : u32;
}

namespace FullscreenUI {
enum class MainWindowType
{
  None,
  Landing,
  GameList,
  Settings,
  QuickMenu,
  Achievements,
};

enum class SettingsPage
{
  InterfaceSettings,
  GameListSettings,
  ConsoleSettings,
  EmulationSettings,
  BIOSSettings,
  ControllerSettings,
  HotkeySettings,
  MemoryCardSettings,
  DisplaySettings,
  EnhancementSettings,
  AudioSettings,
  AdvancedSettings,
  Count
};

enum class NotificationType
{
  GameChanged,
  AchievementProgress,
  AchievementUnlocked,
};

bool Initialize(CommonHostInterface* host_interface, SettingsInterface* settings_interface);
bool HasActiveWindow();
void SystemCreated();
void SystemDestroyed();
void SystemPaused(bool paused);
void OpenQuickMenu();
void CloseQuickMenu();
void Shutdown();
void Render();

bool InvalidateCachedTexture(const std::string& path);

// Returns true if the message has been dismissed.
bool DrawErrorWindow(const char* message);
bool DrawConfirmWindow(const char* message, bool* result);

void EnsureGameListLoaded();

Settings& GetSettingsCopy();
void SaveAndApplySettings();
void SetDebugMenuEnabled(bool enabled, bool save_to_ini = false);

void AddNotification(NotificationType type, float duration, std::string title, std::string text,
                     std::string image_path);

/// Only ImGuiNavInput_Activate, ImGuiNavInput_Cancel, and DPad should be forwarded.
/// Returns true if the UI consumed the event, and it should not execute the normal handler.
bool SetControllerNavInput(FrontendCommon::ControllerNavigationButton button, bool value);

/// Forwards the controller navigation to ImGui for fullscreen navigation. Call before NewFrame().
void SetImGuiNavInputs();

} // namespace FullscreenUI
