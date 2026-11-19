// gcc main.c -o main -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t target __attribute__((aligned(16)));
void *notes[3];
char note_deleted[3];

void menu()
{
    printf("1. create\n");
    printf("2. delete\n");
    printf("3. edit\n");
    printf("4. shell\n");
    printf("> ");
}

void create_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    
    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    note_deleted[idx] = 0;
    notes[idx] = malloc(0x10);
    printf("Note created at %p\n", notes[idx]);
}

void delete_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    
    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }
    
    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }

    if (note_deleted[idx]) {
        printf("No double free!\n");
        return;
    }

    note_deleted[idx] = 1;
    free(notes[idx]);
}

void edit_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }

    printf("Content: ");
    read(STDIN_FILENO, notes[idx], 8);
}

void test_target()
{
    if (target) {
        printf("Win\n");
        system("/bin/sh");
    }
    printf("No\n");
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    printf("[Safe Linking]\n");

    while (1) {
        menu();
        int select;
        scanf("%d", &select);

        switch (select) {
            case 1:
            create_note();
            break;

            case 2:
            delete_note();
            break;

            case 3:
            edit_note();
            break;

            case 4:
            test_target();
            break;

            default:
            printf("Wrong Selection!\n");
        }
    }

}