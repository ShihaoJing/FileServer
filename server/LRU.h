#include <unordered_map>
#include <string>
#include <mutex>
#include <memory>
#include "buffer.h"

class LRUCache {
    struct ListNode {
        std::string key;
        std::shared_ptr<Buffer> value;
        ListNode *pre;
        ListNode *next;
        ListNode(std::string key, std::shared_ptr<Buffer> value) 
            : key(key), value(value), pre(nullptr), next(nullptr) { }
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
    std::unordered_map<std::string, ListNode*> cache_map;
    int cap;
    int size;

    std::mutex cache_lock;

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
    
    std::shared_ptr<Buffer> get(std::string key) {
        std::lock_guard<std::mutex> lock_guard(cache_lock);

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
    
    void put(std::string key, std::shared_ptr<Buffer> value) {
        std::lock_guard<std::mutex> lock_guard(cache_lock);
        
        if (cap == 0) {
            printf("0 cap LRU cache\n");
            return;
        }
        auto it = cache_map.find(key);
        if (it != cache_map.end()) {
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
            printf("add a new item to LRU cache\n");
            ListNode *new_node = new ListNode(key, value);
            cache_map.insert({key, new_node});
            move_to_head(new_node);
        }
    }
    
    int capacity() { return cap; }

    int count() { return size; }
};