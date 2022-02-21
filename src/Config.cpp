/*
obs-websocket
Copyright (C) 2016-2017	Stéphane Lepin <stephane.lepin@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>
*/

#include <obs-frontend-api.h>

#include <QtCore/QObject>
#include <QtCore/QCryptographicHash>
#include <QtCore/QTime>
#include <QtWidgets/QSystemTrayIcon>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>

#define SECTION_NAME "StarscapeSocketConf"
#define PARAM_ENABLE "enabled"
#define PARAM_LOCKTOIPV4 "ipv4"
#define PARAM_DEBUG "debug"
#define PARAM_ALERT "alert"
#define PARAM_AUTHREQUIRED "auth"
#define PARAM_SECRET "secret"
#define PARAM_SALT "salt"

#define PARAM_INIT_PORT_NUM 10001
#define PARAM_AUTH_PASS_CODE "Passwd#12345678"

#define GLOBAL_AUTH_SETUP_PROMPTED "starscape_auth_init"

#include "Utils.h"
#include "WSServer.h"

#include "Config.h"

#define QT_TO_UTF8(str) str.toUtf8().constData()

Config::Config() :
	ServerEnabled(true),
	ServerPort(PARAM_INIT_PORT_NUM),
	LockToIPv4(false),
	DebugEnabled(true),
	AlertsEnabled(true),
	AuthRequired(true),
	Secret(""),
	Salt(""),
	SettingsLoaded(false)
{
	qsrand(QTime::currentTime().msec());

	SetDefaults();
	SessionChallenge = GenerateSalt();

	obs_frontend_add_event_callback(OnFrontendEvent, this);
	SetPassword(QString(PARAM_AUTH_PASS_CODE));
	Save();
}

Config::~Config()
{
	obs_frontend_remove_event_callback(OnFrontendEvent, this);
}

void Config::Load()
{
	config_t* obsConfig = GetConfigStore();

	ServerEnabled = config_get_bool(obsConfig, SECTION_NAME, PARAM_ENABLE);
	LockToIPv4 = config_get_bool(obsConfig, SECTION_NAME, PARAM_LOCKTOIPV4);

	DebugEnabled = config_get_bool(obsConfig, SECTION_NAME, PARAM_DEBUG);
	AlertsEnabled = config_get_bool(obsConfig, SECTION_NAME, PARAM_ALERT);
}

void Config::Save()
{
	config_t* obsConfig = GetConfigStore();

	config_set_bool(obsConfig, SECTION_NAME, PARAM_ENABLE, ServerEnabled);
	config_set_bool(obsConfig, SECTION_NAME, PARAM_LOCKTOIPV4, LockToIPv4);

	config_set_bool(obsConfig, SECTION_NAME, PARAM_DEBUG, DebugEnabled);
	config_set_bool(obsConfig, SECTION_NAME, PARAM_ALERT, AlertsEnabled);

	config_save(obsConfig);
}

void Config::SetDefaults()
{
	// OBS Config defaults
	config_t* obsConfig = GetConfigStore();
	if (obsConfig) {
		config_set_default_bool(obsConfig,
			SECTION_NAME, PARAM_ENABLE, ServerEnabled);
		config_set_default_bool(obsConfig,
			SECTION_NAME, PARAM_LOCKTOIPV4, LockToIPv4);

		config_set_default_bool(obsConfig,
			SECTION_NAME, PARAM_DEBUG, DebugEnabled);
		config_set_default_bool(obsConfig,
			SECTION_NAME, PARAM_ALERT, AlertsEnabled);

		config_set_default_bool(obsConfig,
			SECTION_NAME, PARAM_AUTHREQUIRED, AuthRequired);
		config_set_default_string(obsConfig,
			SECTION_NAME, PARAM_SECRET, QT_TO_UTF8(Secret));
		config_set_default_string(obsConfig,
			SECTION_NAME, PARAM_SALT, QT_TO_UTF8(Salt));
	}
}

config_t* Config::GetConfigStore()
{
	return obs_frontend_get_profile_config();
}

void Config::MigrateFromGlobalSettings()
{
	config_t* source = obs_frontend_get_global_config();
	config_t* destination = obs_frontend_get_profile_config();

	if(config_has_user_value(source, SECTION_NAME, PARAM_ENABLE)) {
		bool value = config_get_bool(source, SECTION_NAME, PARAM_ENABLE);
		config_set_bool(destination, SECTION_NAME, PARAM_ENABLE, value);

		config_remove_value(source, SECTION_NAME, PARAM_ENABLE);
	}
	
	if(config_has_user_value(source, SECTION_NAME, PARAM_LOCKTOIPV4)) {
		bool value = config_get_bool(source, SECTION_NAME, PARAM_LOCKTOIPV4);
		config_set_bool(destination, SECTION_NAME, PARAM_LOCKTOIPV4, value);

		config_remove_value(source, SECTION_NAME, PARAM_LOCKTOIPV4);
	}

	if(config_has_user_value(source, SECTION_NAME, PARAM_DEBUG)) {
		bool value = config_get_bool(source, SECTION_NAME, PARAM_DEBUG);
		config_set_bool(destination, SECTION_NAME, PARAM_DEBUG, value);

		config_remove_value(source, SECTION_NAME, PARAM_DEBUG);
	}

	if(config_has_user_value(source, SECTION_NAME, PARAM_ALERT)) {
		bool value = config_get_bool(source, SECTION_NAME, PARAM_ALERT);
		config_set_bool(destination, SECTION_NAME, PARAM_ALERT, value);

		config_remove_value(source, SECTION_NAME, PARAM_ALERT);
	}

	if(config_has_user_value(source, SECTION_NAME, PARAM_AUTHREQUIRED)) {
		bool value = config_get_bool(source, SECTION_NAME, PARAM_AUTHREQUIRED);
		config_set_bool(destination, SECTION_NAME, PARAM_AUTHREQUIRED, value);

		config_remove_value(source, SECTION_NAME, PARAM_AUTHREQUIRED);
	}

	if(config_has_user_value(source, SECTION_NAME, PARAM_SECRET)) {
		const char* value = config_get_string(source, SECTION_NAME, PARAM_SECRET);
		config_set_string(destination, SECTION_NAME, PARAM_SECRET, value);

		config_remove_value(source, SECTION_NAME, PARAM_SECRET);
	}

	if(config_has_user_value(source, SECTION_NAME, PARAM_SALT)) {
		const char* value = config_get_string(source, SECTION_NAME, PARAM_SALT);
		config_set_string(destination, SECTION_NAME, PARAM_SALT, value);

		config_remove_value(source, SECTION_NAME, PARAM_SALT);
	}

	config_save(destination);
}

QString Config::GenerateSalt()
{
	// Generate 32 random chars
	const size_t randomCount = 32;
	QByteArray randomChars;
	for (size_t i = 0; i < randomCount; i++) {
		randomChars.append((char)qrand());
	}

	// Convert the 32 random chars to a base64 string
	QString salt = randomChars.toBase64();

	return salt;
}

QString Config::GenerateSecret(QString password, QString salt)
{
	// Concatenate the password and the salt
	QString passAndSalt = "";
	passAndSalt += password;
	passAndSalt += salt;

	// Generate a SHA256 hash of the password and salt
	auto challengeHash = QCryptographicHash::hash(
		passAndSalt.toUtf8(),
		QCryptographicHash::Algorithm::Sha256
	);

	// Encode SHA256 hash to Base64
	QString challenge = challengeHash.toBase64();

	return challenge;
}

void Config::SetPassword(QString password)
{
	QString newSalt = GenerateSalt();
	QString newChallenge = GenerateSecret(password, newSalt);

	this->Salt = newSalt;
	this->Secret = newChallenge;
}

bool Config::CheckAuth(QString response)
{
	// Concatenate auth secret with the challenge sent to the user
	QString challengeAndResponse = "";
	challengeAndResponse += Secret;
	challengeAndResponse += SessionChallenge;

	// Generate a SHA256 hash of challengeAndResponse
	auto hash = QCryptographicHash::hash(
		challengeAndResponse.toUtf8(),
		QCryptographicHash::Algorithm::Sha256
	);

	// Encode the SHA256 hash to Base64
	QString expectedResponse = hash.toBase64();

	bool authSuccess = false;
	if (response == expectedResponse) {
		SessionChallenge = GenerateSalt();
		authSuccess = true;
	}

	return authSuccess;
}

void Config::OnFrontendEvent(enum obs_frontend_event event, void* param)
{
	auto config = reinterpret_cast<Config*>(param);

	if (event == OBS_FRONTEND_EVENT_PROFILE_CHANGED) {
		obs_frontend_push_ui_translation(obs_module_get_string);
		QString startMessage = QObject::tr("OBSWebsocket.ProfileChanged.Started");
		QString stopMessage = QObject::tr("OBSWebsocket.ProfileChanged.Stopped");
		QString restartMessage = QObject::tr("OBSWebsocket.ProfileChanged.Restarted");
		obs_frontend_pop_ui_translation();

		bool previousEnabled = config->ServerEnabled;
		bool previousLock = config->LockToIPv4;

		config->SetDefaults();
		config->Load();

		if (config->ServerEnabled != previousEnabled || config->LockToIPv4 != previousLock) {
			auto server = GetServer();
			server->stop();

			if (config->ServerEnabled) {
				server->start(config->ServerPort, config->LockToIPv4);
			} 
		}
	}
	else if (event == OBS_FRONTEND_EVENT_FINISHED_LOADING) {
		FirstRunPasswordSetup();
	}
}

void Config::FirstRunPasswordSetup()
{
	// check if we already showed the auth setup prompt to the user, independently of the current settings (tied to the current profile)
	config_t* globalConfig = obs_frontend_get_global_config();
	bool alreadyPrompted = config_get_bool(globalConfig, SECTION_NAME, GLOBAL_AUTH_SETUP_PROMPTED);
	if (alreadyPrompted) {
		return;
	}

	// lift the flag up and save it
	config_set_bool(globalConfig, SECTION_NAME, GLOBAL_AUTH_SETUP_PROMPTED, true);
	config_save(globalConfig);

	// check if the password is already set
	auto config = GetConfig();
	if (!config) {
		blog(LOG_INFO, "WSServer::Config: failed to get Config file!");

		return;
	}

	if (!(config->Secret.isEmpty()) && !(config->Salt.isEmpty())) {
		blog(LOG_INFO, "WSServer::Config:Auth code is not empty so will not be re-initiated!!");

		return;
	}
}
