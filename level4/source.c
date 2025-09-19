#include <stdio.h>
#include <stdlib.h>

void p(char *param_1, unsigned int m )
{
  m = printf(param_1);
  return;
}


void n(void)
{
  char buffer [520];
  unsigned int m = 0;
  
  fgets(buffer,512,stdin);
  p(buffer, m);
  if (m == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

void main(void)
{
  n();
  return;
}