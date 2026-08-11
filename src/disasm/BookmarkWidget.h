#pragma once

#include <fidra/Types.h>
#include <QWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QToolBar>
#include <QMap>
#include <QColor>
#include <QDateTime>
#include <QJsonObject>

namespace Fidra {

class AnalysisDatabase;

struct Bookmark {
    Address Addr;
    QString Name;
    QString Description;
    QColor Color;
    QString Category;
    QDateTime Created;
};

class BookmarkWidget : public QWidget {
    Q_OBJECT

public:
    explicit BookmarkWidget(QWidget* Parent = nullptr);
    ~BookmarkWidget() override;

    void AddBookmark(Address Addr, const QString& Name, const QString& Desc = {},
                     const QColor& Color = QColor(255, 200, 50), const QString& Category = "Default");
    void RemoveBookmark(Address Addr);
    bool HasBookmark(Address Addr) const;
    Bookmark GetBookmark(Address Addr) const;
    QList<Bookmark> GetAllBookmarks() const;

    void SetAnalysisDatabase(AnalysisDatabase* Db);

    QJsonObject SaveToJson() const;
    void LoadFromJson(const QJsonObject& Root);

signals:
    void NavigateToAddress(Address Addr);
    void BookmarkAdded(Address Addr);
    void BookmarkRemoved(Address Addr);

private slots:
    void OnItemDoubleClicked(QTreeWidgetItem* Item, int Column);
    void OnFilterChanged(const QString& Text);
    void OnContextMenu(const QPoint& Pos);
    void OnAddBookmark();
    void OnRemoveSelected();
    void OnClearAll();
    void OnImport();
    void OnExport();

protected:
    void keyPressEvent(QKeyEvent* Event) override;

private:
    void RefreshTree();
    void ShowEditDialog(Address Addr);
    QTreeWidgetItem* FindCategoryItem(const QString& Category);
    QTreeWidgetItem* CreateCategoryItem(const QString& Category);
    QString FormatAddress(Address Addr) const;

    QTreeWidget* TreeWidget;
    QLineEdit* FilterInput;
    QToolBar* ToolBar;
    QMap<Address, Bookmark> Bookmarks;
    AnalysisDatabase* Database;
};

}
