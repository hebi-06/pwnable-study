a1 = [
  36,
  39,
  19,
  198,
  198,
  19,
  22,
  230,
  71,
  245,
  38,
  150,
  71,
  245,
  70,
  39,
  19,
  38,
  38,
  198,
  86,
  245,
  195,
  195,
  245,
  227,
  227,
  0,
  0,
  0,
  0,
  0]
'''
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x28; ++i )
  {
    if ( ((16 * a1[i]) | (a1[i] >> 4)) != byte_140003000[i] )
      return 0;
  }
  return 1;
}
'''
for i in range(0, 27):
    a1[i] = (16 / a1[i]) or (a1[i] << 4)
for i in range(0, 27):
    print(chr(int(a1[i])))

for i in range(0, 27):
    a1[i] ^= 0x30
for i in range(0, 27):
    print(chr(a1[i]))


