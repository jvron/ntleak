#include <windows.h>
#include <memoryapi.h>
#include <iostream>
#include "alloc_map.h"


HashTable::HashTable()
{
    table = (AllocRecord*) VirtualAlloc(NULL, hashGroups * sizeof(AllocRecord), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (table == nullptr)
    {
        std::cerr << "table alloc failed, error: " << GetLastError() << "\n";
        table = nullptr;
        return;
    }
    //initialize all records to zero
    memset(table, 0, hashGroups * sizeof(AllocRecord));
}

HashTable::~HashTable()
{   
    BOOL result = 1;

    if (table != nullptr)
    {
       result = VirtualFree(table, 0, MEM_RELEASE);
    }
    
    if (table == nullptr || result == 0)
    {
        std::cerr << " Table VirtualFree failed\n";
        return;
    }

    table = nullptr;
}

bool HashTable::isEmpty()
{
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
    int hVal = h(ptr);
    hVal = hVal % hashGroups;

    if (hVal < 0)
    {
        hVal += hashGroups;
    }

    return hVal;
}

void HashTable::insertItem(void* ptr, AllocRecord record)
{   
    if (table == nullptr)
    {
        //std::cerr << "ERROR: table is null!\n";
        return;
    }

    int hashValue = hashFunction(ptr);
    int start = hashValue;



    //two different keys can map to the same hash - collision

    while (table[hashValue].status == USED) //check if the slot is used 
    {   
       // printf("INSERT hashValue: %i for ptr: %p\n", hashValue, ptr);

        if (table[hashValue].address == ptr) // to avoid duplicates we replace the record
        {   
            table[hashValue] = record;
            table[hashValue].status = USED;
            return;
        }

        hashValue = (hashValue + 1) % hashGroups; //modulus so that we dont go past the capacity

        if (hashValue == start) //full circle - list is full
        {
            break;
        }

        if (table[hashValue].status == DELETED || table[hashValue].status == EMPTY) // reuse deleted or empty slot 
        {
            table[hashValue] = record; 
            table[hashValue].status = USED; 
            return;
        }
    }

    table[hashValue] = record;
    table[hashValue].status = USED;
    //printf("INSERT hashValue: %i for ptr: %p\n", hashValue, ptr);
}

void HashTable::deleteItem(void* ptr)
{
    int hashValue = hashFunction(ptr);

    while (table[hashValue].status == USED)
    {
        if (table[hashValue].address == ptr)
        {
            table[hashValue].status = DELETED;
        }
        
        hashValue = (hashValue + 1) % hashGroups;

        if (table[hashValue].status == DELETED || table[hashValue].status == EMPTY)
        {   
            hashValue++;
            continue;
        }
    }

    table[hashValue].status = DELETED;
}

AllocRecord* HashTable::searchTable(void* ptr)
{
    int hashValue = hashFunction(ptr);

    int start = hashValue;

    //printf("SEARCH hashValue: %i for ptr: %p\n", hashValue, ptr);


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

        if (table[hashValue].status == DELETED || table[hashValue].status == EMPTY)
        {
            hashValue++; //skip deleted and empty records
        }

        if (hashValue == start)
        {
            break;
        }
    }

    return  nullptr;
}

