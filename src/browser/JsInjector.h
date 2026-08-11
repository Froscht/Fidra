#pragma once

#include <QObject>
#include <QString>
#include <QList>
#include <QWebEngineScript>
#include <QWebEngineProfile>
#include <QDialog>
#include <QPlainTextEdit>

class QLineEdit;
class QComboBox;
class QCheckBox;

namespace Fidra {

struct UserScript {
    QString Name;
    QString Code;
    bool Enabled;
    QWebEngineScript::InjectionPoint InjectionPoint;
    int WorldId;
};

class ScriptEditorDialog : public QDialog {
    Q_OBJECT

public:
    explicit ScriptEditorDialog(QWidget* Parent = nullptr);
    ~ScriptEditorDialog() override;

    void SetScript(const UserScript& Script);
    UserScript GetScript() const;

private:
    void SetupUi();

    QLineEdit* NameEdit;
    QPlainTextEdit* CodeEdit;
    QComboBox* InjectionPointCombo;
    QCheckBox* EnabledCheck;
};

class JsInjector : public QObject {
    Q_OBJECT

public:
    explicit JsInjector(QWebEngineProfile* Profile, QObject* Parent = nullptr);
    ~JsInjector() override;

    void InjectScript(const QWebEngineScript& Script);
    void RemoveScript(const QString& Name);
    void ClearAllScripts();

    void InjectConsoleHook();
    void InjectXhrHook();
    void InjectFetchHook();
    void InjectWebSocketHook();
    void InjectAllHooks();

    void AddUserScript(const UserScript& Script);
    void RemoveUserScript(const QString& Name);
    void UpdateUserScript(const UserScript& Script);
    QList<UserScript> GetUserScripts() const;

    void ShowScriptEditor(QWidget* Parent);

signals:
    void ConsoleMessage(const QString& Level, const QString& Message);
    void XhrCaptured(const QString& Method, const QString& Url, int Status, const QString& Response);
    void FetchCaptured(const QString& Method, const QString& Url, int Status, const QString& Response);
    void WebSocketMessage(const QString& Url, const QString& Direction, const QString& Data);
    void ScriptError(const QString& ScriptName, const QString& Error);

private:
    QWebEngineScript CreateScript(const QString& Name, const QString& Source, QWebEngineScript::InjectionPoint Point, int WorldId = 0);
    void ReloadUserScripts();

    QWebEngineProfile* TargetProfile;
    QList<UserScript> UserScripts;
};

}
