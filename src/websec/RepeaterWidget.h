#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QNetworkAccessManager>
#include <QList>

namespace Fidra {

class SingleRepeaterTab : public QWidget {
    Q_OBJECT

public:
    explicit SingleRepeaterTab(QWidget* Parent = nullptr);
    ~SingleRepeaterTab() override;

    void SetRequest(const HttpRequest& Request);
    void SetRawRequest(const QString& Raw);

signals:
    void RequestSent(const HttpRequest& Result);

private slots:
    void OnSendClicked();

private:
    HttpRequest ParseRawRequest(const QString& Raw);
    QString FormatResponse(const HttpRequest& Result);

    QPlainTextEdit* RequestEditor;
    QPlainTextEdit* ResponseViewer;
    QPushButton* SendButton;
    QLabel* StatusLabel;
    QLabel* TimeLabel;
    QLabel* SizeLabel;
    QNetworkAccessManager* NetworkManager;
    QList<HttpRequest> TabHistory;
};

class RepeaterWidget : public QWidget {
    Q_OBJECT

public:
    explicit RepeaterWidget(QWidget* Parent = nullptr);
    ~RepeaterWidget() override;

    void AddTab(const HttpRequest& Request);
    void AddEmptyTab();

private:
    QTabWidget* TabBar;
    int TabCounter;
};

}
