#ifndef ZKINTERFACE_H
#define ZKINTERFACE_H

#if defined(_WIN32)
  #ifndef APICALL
    #define APICALL __stdcall
  #endif
  #ifndef ZKINTERFACE
    #if defined(_USRDLL) || defined(_WINDLL)
      #define ZKINTERFACE __declspec(dllexport)
    #else
      #define ZKINTERFACE __declspec(dllimport)
    #endif
  #endif
#else
  #ifndef APICALL
    #define APICALL
  #endif
  #ifndef ZKINTERFACE
    #define ZKINTERFACE __attribute__((visibility("default")))
  #endif
#endif

#endif
