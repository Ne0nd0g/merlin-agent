# Windows

This directory is used to store functions exclusively used with the Windows agent.
It consists of two high-level directories:

- `api` - This directory stores low-level Win32 API calls without wrapper functionality; All checks should be performed prior to calling
- `pkg` - This directory stores high-level functions that sometimes wrap Win32 API calls
