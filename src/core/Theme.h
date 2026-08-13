#pragma once

#include <QApplication>
#include <QString>

namespace Fidra {

class Theme {
public:
    static void Apply(QApplication* App);
    static QString GetStyleSheet();
};

}
