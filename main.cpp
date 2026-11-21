#include <QApplication>
#include "MainWindow.h"

// Function defined in tests.cpp
int runTests(int argc, char **argv);

int main(int argc, char *argv[]) {
    // Uncomment to run tests instead of the UI
    // return runTests(argc, argv);

    QApplication app(argc, argv);
    MainWindow window;
    window.show();
    return app.exec();
}