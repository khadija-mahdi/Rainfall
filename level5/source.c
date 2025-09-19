void o(void)
{
  system("/bin/sh");
  _exit(1);
}


void n(void)
{
  char buffer [520];
  
  fgets(buffer,0x200,stdin);
  printf(buffer);
  exit(1);
}

void main(void)

{
  n();
  return;
}