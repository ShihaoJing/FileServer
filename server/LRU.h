#include <unordered_map>
#include <string>
#include "buffer.h"

using namespace std;

class LRUCache {
    struct ListNode {
        string key;
        Buffer *value;
        ListNode *pre;
        ListNode *next;
        ListNode(string key, Buffer *value) 
            : key(key), value(value), pre(nullptr), next(nullptr) { }
        ~ListNode() {
            buffer_free(value);
        }
    };
    
    void move_to_head(ListNode *node) {
        node->next = head->next;
        head->next = node;
        node->next->pre = node;
        node->pre = head;
    }
    
    ListNode* remove_from_list(ListNode *node) {
        node->pre->next = node->next;
        node->next->pre = node->pre;
        return node;
    }
    
    ListNode *head;
    ListNode *tail;
    unordered_map<string, ListNode*> cache_map;
    int cap;
    int size;
public:
    LRUCache(int capacity) 
        : cap(capacity), size(0), head(new ListNode("", nullptr)), tail(new ListNode("", nullptr))
    {
        head->next = tail;
        tail->pre = head;
    }

    ~LRUCache()
    {
        delete head;
        delete tail;
    }
    
    Buffer* get(string key) {
        if (cap == 0) {
            return nullptr;
        }
        auto it = cache_map.find(key);
        if (it == cache_map.end())
            return nullptr;
        remove_from_list(it->second);
        move_to_head(it->second);
        return it->second->value;
    }
    
    void put(string key, Buffer* value) {
        if (cap == 0) {
            return;
        }
        auto it = cache_map.find(key);
        if (it != cache_map.end()) {
            buffer_free(it->second->value);
            it->second->value = value;
            remove_from_list(it->second);
            move_to_head(it->second);
        }
        else {
            if (size++ == cap) {
                auto LRU = remove_from_list(tail->pre);
                cache_map.erase(LRU->key);
                --size;
            }
            ListNode *new_node = new ListNode(key, value);
            cache_map.insert({key, new_node});
            move_to_head(new_node);
        }
     }
};