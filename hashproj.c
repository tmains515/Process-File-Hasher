#ifndef GRADING_MODE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

#define BLOCK_SIZE 1024
#define SYMBOLS 256
#define LARGE_PRIME 2147483647   // for modular hash
#define UMEM_SIZE (128 * 1024)   // 128 KB managed heap for Step 2

/* Forward declarations for student functions*/
void *umalloc(size_t size);
void ufree(void *ptr);
unsigned long process_block(const unsigned char *buf, size_t len);
int run_single(const char *filename);
int run_multi(const char *filename);


/* =======================================================================
   PROVIDED CODE — DO NOT MODIFY
   -----------------------------------------------------------------------
   This section implements the complete Huffman tree construction logic
   and internal data structures.  It uses umalloc() and ufree() for all
   dynamic memory so that your allocator can be substituted later without
   touching this code.
   ======================================================================= */

/* ============================ STEP 2 ONLY ==============================
   The function and structures below will be used in Step 2 when you build
   your own memory allocator.  DO NOT USE OR MODIFY THIS CODE IN STEP 1.

   In Step 2, you will:
     - Use init_umem() to allocate a contiguous memory region.
     - Implement a FIRST-FIT allocator using the structures below.
     - Manage all memory inside this region manually.
   ======================================================================= */

void *init_umem(void) {
    void *ptr = mmap(NULL, UMEM_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    return ptr;
}

#define MAGIC 0xDEADBEEFLL  // integrity check pattern

typedef struct {
    long size;   // Size of the block (payload only)
    long magic;  // Magic number for integrity check
} header_t;

typedef struct __node_t {
    long size;               // Size of the free block
    struct __node_t *next;   // Pointer to the next free block
} node_t;

/* =======================================================================
   Huffman and Heap Infrastructure (Given)
   ======================================================================= */

typedef struct Node {
    unsigned char symbol;
    unsigned long freq;
    struct Node *left, *right;
} Node;

typedef struct {
    Node **data;
    int size;
    int capacity;
} MinHeap;

MinHeap *heap_create(int capacity) {
    MinHeap *h = umalloc(sizeof(MinHeap));
    h->data = umalloc(sizeof(Node *) * capacity);
    h->size = 0;
    h->capacity = capacity;
    return h;
}

void heap_swap(Node **a, Node **b) {
    Node *tmp = *a; *a = *b; *b = tmp;
}

void heap_push(MinHeap *h, Node *node) {
    int i = h->size++;
    h->data[i] = node;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (h->data[p]->freq < h->data[i]->freq) break;
        heap_swap(&h->data[p], &h->data[i]);
        i = p;
    }
}

Node *heap_pop(MinHeap *h) {
    if (h->size == 0) return NULL;
    Node *min = h->data[0];
    h->data[0] = h->data[--h->size];
    int i = 0;
    while (1) {
        int l = 2 * i + 1, r = l + 1, smallest = i;
        if (l < h->size && h->data[l]->freq < h->data[smallest]->freq) smallest = l;
        if (r < h->size && h->data[r]->freq < h->data[smallest]->freq) smallest = r;
        if (smallest == i) break;
        heap_swap(&h->data[i], &h->data[smallest]);
        i = smallest;
    }
    return min;
}

void heap_free(MinHeap *h) {
    ufree(h->data);
    ufree(h);
}

Node *new_node(unsigned char sym, unsigned long freq, Node *l, Node *r) {
    Node *n = umalloc(sizeof(Node));
    n->symbol = sym;
    n->freq = freq;
    n->left = l;
    n->right = r;
    return n;
}

void free_tree(Node *n) {
    if (!n) return;
    free_tree(n->left);
    free_tree(n->right);
    ufree(n);
}

Node *build_tree(unsigned long freq[SYMBOLS]) {
    MinHeap *h = heap_create(SYMBOLS);
    for (int i = 0; i < SYMBOLS; i++)
        if (freq[i] > 0)
            heap_push(h, new_node((unsigned char)i, freq[i], NULL, NULL));
    if (h->size == 0) {
        heap_free(h);
        return NULL;
    }
    while (h->size > 1) {
        Node *a = heap_pop(h);
        Node *b = heap_pop(h);
        Node *p = new_node(0, a->freq + b->freq, a, b);
        heap_push(h, p);
    }
    Node *root = heap_pop(h);
    heap_free(h);
    return root;
}

unsigned long hash_tree(Node *n, unsigned long hash) {
    if (!n) return hash;
    hash = (hash * 31 + n->freq + n->symbol) % LARGE_PRIME;
    hash = hash_tree(n->left, hash);
    hash = hash_tree(n->right, hash);
    return hash;
}

/* =======================================================================
   PROVIDED PRINTING UTILITIES (DO NOT MODIFY)
   -----------------------------------------------------------------------
   These helper functions standardize all program output for testing and
   grading. Students must call these rather than using printf() directly
   for block or final output.
   ======================================================================= */

void print_intermediate(int block_num, unsigned long hash, pid_t pid) {
#ifdef DEBUG
#  if DEBUG == 2
    printf("[PID %d] Block %d hash: %lu\n", pid, block_num, hash);
#  elif DEBUG == 1
    printf("Block %d hash: %lu\n", block_num, hash);
#  endif
#else
    (void)block_num;
    (void)hash;
    (void)pid;
#endif
}

void print_final(unsigned long final_hash) {
    printf("Final signature: %lu\n", final_hash);
}

/* =======================================================================
   MAIN DISPATCH FUNCTION
   -----------------------------------------------------------------------
   Usage:
       ./hashproj <file>          -> run single-process version
       ./hashproj <file> -m       -> run multi-process version
   ======================================================================= */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [-m]\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    int use_multi = (argc >= 3 && strcmp(argv[2], "-m") == 0);

    if (use_multi)
        return run_multi(filename);
    else
        return run_single(filename);
}

#endif //GRADING_MODE

/* =======================================================================
   STUDENT SECTION — IMPLEMENT THE FUNCTIONS BELOW
   -----------------------------------------------------------------------
   In Step 1 you will implement umalloc() and ufree() as simple wrappers
   around malloc() and free(). In Step 2, you will replace these with your
   own FIRST-FIT allocator that operates inside the region returned by
   init_umem().
   ======================================================================= */

void *umalloc(size_t size) {
    return malloc(size);
}

void ufree(void *ptr) {
    free(ptr);
}


unsigned long process_block(const unsigned char *buf, size_t len) {
    /* -------------------------------------------------------------------
       TODO: Implement the logic to process one block of input data.

       Each block is a sequence of bytes of length `len`. Your goal is to:
         1. Count how many times each symbol (0–255) appears in the block.
         2. Build a Huffman tree based on these frequencies.
         3. Compute a hash value of the resulting tree using hash_tree().
         4. Free the tree before returning.
    ------------------------------------------------------------------- */

    /* Step 1: Initialize frequency table for all 256 possible symbols.
       Each index corresponds to an unsigned char value (0–255). */
    unsigned long freq[SYMBOLS] = {0};

    /* Step 2: Count symbol frequencies in this block. */
    for (size_t i = 0; i < len; i++) {
        /* TODO: Increment frequency for symbol buf[i] */

        freq[buf[i]]++;
    }

    /* Step 3: Build Huffman tree using provided build_tree() function.
       Pass in the frequency array you just filled. */
    Node *root = build_tree(freq);  /* TODO: call build_tree(freq) */


    /* Step 4: Compute hash of the tree using provided hash_tree().
       Start with an initial hash value of 0. */
    unsigned long h = 0;  /* TODO: call hash_tree(root, 0) */
    unsigned long block_hash = hash_tree(root, 0);


    /* Step 5: Free the Huffman tree to avoid memory leaks. */
    /* TODO: call free_tree(root) */

    free_tree(root);

    /* Step 6: Return the computed hash value for this block. */
    return block_hash;  /* Replace with your hash variable */
}

/* -------------------------------------------------------------------
   TODO: Implement run_single()

   The single-process version should:
     1. Open the specified input file in binary mode.
     2. Read it in chunks of BLOCK_SIZE bytes into a local buffer.
     3. For each block:
          - Call process_block() to compute its hash.
          - Print the result using print_intermediate(block_num, hash, getpid()).
          - Accumulate the hashes into a final signature using modular addition:
                final_hash = (final_hash + hash) % LARGE_PRIME;
     4. After processing all blocks:
          - Close the input file.
          - Print the final signature with print_final(final_hash).
     5. Handle any file errors (e.g., fopen failure).
------------------------------------------------------------------- */
int run_single(const char *filename) {
    
    FILE* fd;
    size_t bytes_read;
    unsigned char* buffer;

    // Open in 'read binary' mode
    fd = fopen(filename, "rb");

    if(fd == NULL){
        fprintf(stderr, "No file was found");
        return 1;
    }

    int block_num = 0;

    unsigned long computed_hash = 0;
    int j =0;
    buffer = (unsigned char*)malloc(BLOCK_SIZE);

    // Read file into buffer
    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, fd)) > 0) {        

        // Raw hash
        unsigned long hash = process_block(buffer, bytes_read);

        print_intermediate(block_num++, hash, getpid());

        // computed hash
        computed_hash = (computed_hash + hash) % LARGE_PRIME;
    }
    
    if (buffer == NULL) {
        fprintf(stderr, "Could not allocate memory");
        fclose(fd);
        return 1;
    }

    fclose(fd);

    print_final(computed_hash);

    free(buffer);

    return 0;
}

/* -------------------------------------------------------------------
   TODO: Implement run_multi()

   The multi-process version should:
     1. Open the specified input file in binary mode.
     2. Read it in chunks of BLOCK_SIZE bytes into a local buffer.
     3. For each block:
          - Create a pipe for communication between parent and child.
          - Fork a new process.
          - In the child process:
                * Close the read end of the pipe.
                * Call process_block() on the buffer.
                * Write the resulting hash to the pipe.
                * Close the write end and exit.
          - In the parent process:
                * Close the write end of the pipe.
                * Read the hash value from the pipe.
                * Close the read end.
                * Print the result using print_intermediate(block_num, hash, pid).
                * Add the hash into the running total:
                      final_hash = (final_hash + hash) % LARGE_PRIME;
     4. After processing all blocks:
          - Wait for all child processes to finish using waitpid().
          - Close the input file.
          - Print the final signature with print_final(final_hash).
     5. Handle all errors (e.g., fopen, pipe, or fork failures) gracefully.
------------------------------------------------------------------- */

int run_multi(const char *filename) {
    return 0;
}

