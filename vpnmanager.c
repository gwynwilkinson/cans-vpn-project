#include <ncurses.h>
#include <stdlib.h>
#include <menu.h>
#include <memory.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

char *choices[] = {
        "Display Current Connections",
        "???",
        "Profit!!",
        "Exit",
        (char *) NULL,
};

void printInMiddle(WINDOW *win, int starty, int startx, int width, char *string, chtype color);

void func(char *name);

int main(int argc, char *argv[]) {
    ITEM **my_items;
    int c;
    MENU *mainMenu;
    WINDOW *mainWindow;
    int numChoices, i;
    int width, height;
    int boxHeight, boxWidth;

    char helpText1[] = "Press <ENTER> to see the option selected";
    char helpText2[] = "Up and Down arrow keys to naviage (F1 to Exit)";

    /* Initialize curses */
    initscr();
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    init_pair(1, COLOR_BLUE, COLOR_BLACK);
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
    init_pair(3, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(4, COLOR_WHITE, COLOR_BLACK);

    getmaxyx(stdscr, height, width);
    boxHeight = (height / 3) * 2;
    boxWidth = (width / 3) * 2;

    /* Create items */
    numChoices = ARRAY_SIZE(choices);
    my_items = (ITEM **) calloc(numChoices, sizeof(ITEM *));
    for (i = 0; i < numChoices; ++i) {
        my_items[i] = new_item(choices[i], "");
        /* Set the user pointer */
        set_item_userptr(my_items[i], func);
    }

    /* Create menu */
    mainMenu = new_menu((ITEM **) my_items);

    /* Create the window to be associated with the menu */
    mainWindow = newwin(boxHeight, boxWidth, height / 2 - (boxHeight / 2), width / 2 - (boxWidth / 2));
    keypad(mainWindow, TRUE);

    /* Set main window and sub window */
    set_menu_win(mainMenu, mainWindow);
    set_menu_sub(mainMenu, derwin(mainWindow, 6, 38, ((boxHeight - 4) / 2), ((boxWidth - 2) / 2) - 19));
    set_menu_format(mainMenu, 5, 1);

    /* Set menu mark to the string " * " */
    set_menu_mark(mainMenu, " * ");

    /* Print a border around the main window and print a title */
    box(mainWindow, 0, 0);
    printInMiddle(mainWindow, 1, 0, boxWidth, "VPN Menu", COLOR_PAIR(1));
    mvwaddch(mainWindow, 2, 0, ACS_LTEE);
    mvwhline(mainWindow, 2, 1, ACS_HLINE, boxWidth - 2);
    mvwaddch(mainWindow, 2, boxWidth - 1, ACS_RTEE);

    /* Post the menu */
    post_menu(mainMenu);
    wrefresh(mainWindow);

    printInMiddle(stdscr, LINES - 3, 0, width, helpText1, COLOR_PAIR(1));
    printInMiddle(stdscr, LINES - 2, 0, width, helpText2, COLOR_PAIR(1));

    refresh();

    while ((c = wgetch(mainWindow)) != KEY_F(1)) {
        switch (c) {
            case KEY_DOWN:
                menu_driver(mainMenu, REQ_DOWN_ITEM);
                break;
            case KEY_UP:
                menu_driver(mainMenu, REQ_UP_ITEM);
                break;
            case 10: /* Enter */
            {
                ITEM *cur;
                void (*p)(char *);

                cur = current_item(mainMenu);
                p = item_userptr(cur);
                p((char *) item_name(cur));
                pos_menu_cursor(mainMenu);
                break;
            }

            default:
                break;
        }

        wrefresh(mainWindow);
    }

    /* Unpost and free all the memory taken up */
    unpost_menu(mainMenu);
    free_menu(mainMenu);

    for (i = 0; i < numChoices; ++i) {
        free_item(my_items[i]);
    }

    endwin();
}

void printInMiddle(WINDOW *win, int starty, int startx, int width, char *string, chtype color) {
    int length, x, y;
    float temp;

    if (win == NULL)
        win = stdscr;
    getyx(win, y, x);
    if (startx != 0)
        x = startx;
    if (starty != 0)
        y = starty;
    if (width == 0)
        width = 80;

    length = strlen(string);
    temp = (width - length) / 2;
    x = startx + (int) temp;
    wattron(win, color);
    mvwprintw(win, y, x, "%s", string);
    wattroff(win, color);
    refresh();
}

void func(char *name) {

    move(LINES - 5, 0);
    clrtoeol();

    char buffer[255];

    sprintf(buffer, "Item selected is : %s", name);

    printInMiddle(stdscr, LINES - 5, 0, getmaxx(stdscr), buffer, COLOR_PAIR(4));
    refresh();
}
