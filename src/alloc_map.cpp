#include "alloc_map.h"
#include <iostream>
#include <memoryapi.h>

HashTable::HashTable()
{
    table = (AllocRecord*) VirtualAlloc(NULL, hashGroups * sizeof(AllocRecord), MEM_COMMIT, PAGE_READWRITE);
}

HashTable::~HashTable()
{
    BOOL result = VirtualFree(table, 0, MEM_RELEASE);
    
    if (result == 0)
    {
        std::cerr << "virtualFree failed\n";
        return;
    }

    table = nullptr;
}

bool HashTable::isEmpty()
{
    int sum {};

    for (int i = 0; i < hashGroups; i++)
    {   
        
       if (table[i].address != nullptr)
       {
            return false;
       }
    }

    return true;
}

int HashTable::hashFunction(void* ptr)
{
    int h = hash(ptr);
    h = h % hashGroups;

    std::cout << h << "\n";

    return h;
}

void HashTable::insertItem(void* ptr, AllocRecord &record)
{
    int hashValue = hashFunction(ptr);
    int start = hashValue;

    //two different keys can map to the same hash - collision

    while (table[hashValue].status == USED) //check if the slot is used
    {
        if (table[hashValue].address != ptr) // to avoid duplicates we replace the record
        {
            table[hashValue] = record;
            return;
        }

        hashValue = (hashValue + 1) % hashGroups; //modulus so that we dont go past the capacity

        if (hashValue == start) //full circle - list full
        {
            break;
        }

        if (table[hashValue].status == DELETED)
        {
            table[hashValue] = record; 
            table[hashValue].status = USED; // reuse deleted slot
            return;
        }

    }

    table[hashValue] = record;
    table[hashValue].status = USED;

}

void HashTable::deleteItem(void* ptr)
{
    int hashValue = hash(ptr);

    while (table[hashValue].status == USED)
    {
        if (table[hashValue].address == ptr)
        {
            table[hashValue].status = DELETED;
        }
        
        hashValue = (hashValue + 1) % hashGroups;

        if (table[hashValue].status == DELETED)
        {   
            hashValue++;
            continue;
        }
    }

    table[hashValue].status = DELETED;
}

AllocRecord* HashTable::searchTable(void* ptr)
{
    int hashValue = hash(ptr);

    if (table[hashValue].address == ptr)
    {
        return &table[hashValue];
    }

    while(table[hashValue].status == USED)
    {   
        if (table[hashValue].address == ptr )
        {
            return  &table[hashValue];
        }
        else {
        
            hashValue = (hashValue + 1) % hashGroups;
        }

        if (table[hashValue].status == DELETED)
        {
            hashValue++; //skip deleted records
        }
    }

    return  nullptr;
}

