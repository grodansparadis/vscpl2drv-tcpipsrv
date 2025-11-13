# Windows Semaphore Implementation Guide

## Problem
The original code used POSIX semaphores (`sem_post`, `sem_init`, `sem_destroy`, `sem_timedwait`) which are not available on Windows natively.

## Solution
Implemented cross-platform semaphore support using Windows semaphore APIs when building on Windows.

## Changes Made

### 1. Header File Updates (`websocksrv.h`)

**Before:**
```cpp
sem_t m_semInputQueue;
sem_t m_semSendQueue;      
sem_t m_semReceiveQueue;
```

**After:**
```cpp
#ifdef WIN32
HANDLE m_semInputQueue;
HANDLE m_semSendQueue;               
HANDLE m_semReceiveQueue;
#else
sem_t m_semInputQueue;
sem_t m_semSendQueue;               
sem_t m_semReceiveQueue;
#endif
```

### 2. Semaphore Initialization

**Before:**
```cpp
sem_init(&m_semInputQueue, 0, 0);
sem_init(&m_semSendQueue, 0, 0);
sem_init(&m_semReceiveQueue, 0, 0);
```

**After:**
```cpp
#ifdef WIN32
m_semInputQueue = CreateSemaphore(NULL, 0, MAX_ITEMS_IN_QUEUE, NULL);
m_semSendQueue = CreateSemaphore(NULL, 0, MAX_ITEMS_IN_QUEUE, NULL);
m_semReceiveQueue = CreateSemaphore(NULL, 0, MAX_ITEMS_IN_QUEUE, NULL);
#else
sem_init(&m_semInputQueue, 0, 0);
sem_init(&m_semSendQueue, 0, 0);
sem_init(&m_semReceiveQueue, 0, 0);
#endif
```

### 3. Semaphore Posting (Signaling)

**Before:**
```cpp
sem_post(&m_semInputQueue);
sem_post(&m_semSendQueue);
sem_post(&m_semReceiveQueue);
```

**After:**
```cpp
#ifdef WIN32
ReleaseSemaphore(m_semInputQueue, 1, NULL);
ReleaseSemaphore(m_semSendQueue, 1, NULL);
ReleaseSemaphore(m_semReceiveQueue, 1, NULL);
#else
sem_post(&m_semInputQueue);
sem_post(&m_semSendQueue);
sem_post(&m_semReceiveQueue);
#endif
```

### 4. Semaphore Cleanup

**Before:**
```cpp
sem_destroy(&m_semInputQueue);
sem_destroy(&m_semSendQueue);
sem_destroy(&m_semReceiveQueue);
```

**After:**
```cpp
#ifdef WIN32
CloseHandle(m_semInputQueue);
CloseHandle(m_semSendQueue);
CloseHandle(m_semReceiveQueue);
#else
sem_destroy(&m_semInputQueue);
sem_destroy(&m_semSendQueue);
sem_destroy(&m_semReceiveQueue);
#endif
```

### 5. Semaphore Waiting with Timeout

**Before:**
```cpp
struct timespec ts;
clock_gettime(CLOCK_REALTIME, &ts);
// ... timeout calculation ...
sem_timedwait(&m_semSendQueue, &ts);
```

**After:**
```cpp
#ifdef WIN32
// Wait for semaphore with 100ms timeout
if (WaitForSingleObject(m_semSendQueue, 100) == WAIT_OBJECT_0) {
#else
struct timespec ts;
if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
    continue;
}
ts.tv_nsec += 100000000; // 100 ms
if (ts.tv_nsec >= 1000000000) {
    ts.tv_sec++;
    ts.tv_nsec -= 1000000000;
}
if (sem_timedwait(&m_semSendQueue, &ts) == 0) {
#endif
```

### 6. Header Includes

**Added:**
```cpp
#ifndef WIN32
#include <semaphore.h>
#endif
```

## Windows vs POSIX Semaphore Differences

| Operation | POSIX | Windows |
|-----------|-------|---------|
| **Create** | `sem_init(&sem, 0, initial_count)` | `CreateSemaphore(NULL, initial_count, max_count, NULL)` |
| **Signal** | `sem_post(&sem)` | `ReleaseSemaphore(handle, 1, NULL)` |
| **Wait** | `sem_wait(&sem)` | `WaitForSingleObject(handle, INFINITE)` |
| **Timed Wait** | `sem_timedwait(&sem, &timespec)` | `WaitForSingleObject(handle, timeout_ms)` |
| **Destroy** | `sem_destroy(&sem)` | `CloseHandle(handle)` |

## Key Points

1. **Handle Types**: Windows uses `HANDLE`, POSIX uses `sem_t`
2. **Return Values**: Windows APIs have different return value conventions
3. **Timeout Format**: Windows uses milliseconds, POSIX uses `timespec`
4. **Max Count**: Windows requires specifying maximum semaphore count at creation
5. **Error Handling**: Different error codes and handling mechanisms

## Benefits of This Approach

- ✅ **Cross-platform compatibility**: Same code works on Windows and Linux
- ✅ **Native performance**: Uses platform-specific optimized APIs
- ✅ **Maintainable**: Clear separation of platform-specific code
- ✅ **Standard compliance**: Uses each platform's recommended semaphore implementation

## Testing

The changes have been tested and compile successfully on Windows with Visual Studio 2022. The semaphore-related compilation errors have been resolved.