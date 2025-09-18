#include <stdio.h>
#include <stdlib.h>

void p(char *param_1, unsigned int m )
{
  m = printf(param_1);
  return;
}


void n(void)
{
  char local_20c [520];
  unsigned int m = 0;
  
  fgets(local_20c,0x200,stdin);
  p(local_20c, m);
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