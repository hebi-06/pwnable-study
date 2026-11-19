// gcc main.c -o main -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define NOTE_SIZE 256

size_t target = 1234;
size_t dummy = (size_t) &dummy - 0x18;

void *notes[NOTE_SIZE];
char note_deleted[NOTE_SIZE];

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
    int idx, prompt, size;
    printf("idx: ");
    scanf("%d", &idx);
    
    if (idx < 0 || idx > NOTE_SIZE) {
        printf("idx out of range!\n");
        return;
    }

    printf("size (1. tiny, 2. small): ");
    scanf("%d", &prompt);

    switch (prompt) {
        case 1:
            size = 0x20 - 0x8;
            break;
        case 2:
            size = 0x90 - 0x8;
            break;
        default:
            printf("invalid selection!\n");
            return;
    }


    note_deleted[idx] = 0;
    notes[idx] = malloc(size);
    printf("%s note created at index %d\n", prompt == 1 ? "tiny" : "small", idx);
}

void delete_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    
    if (idx < 0 || idx > NOTE_SIZE) {
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

    if (idx < 0 || idx > NOTE_SIZE) {
        printf("idx out of range!\n");
        return;
    }

    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }

    printf("Content: ");
    read(STDIN_FILENO, notes[idx], 16);
}

void test_target()
{
    if (target != 1234) {
        printf("Win\n");
        system("/bin/sh");
    }
    printf("No\n");
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    printf("[Tcache Stashing Unlink]\n");


    int select;

    while (1) {
        menu();
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
