#include<iostream>
#include<cstdlib>
#include<ctime>

using namespace std;

int r = ((static_cast<double>(std::rand()) /RAND_MAX) * 1024 ) + 1;

int main()
{
   srand (time(0));
   for(int i=0;i<1024;i++)
   {
      r = ((static_cast<double>(std::rand()) /RAND_MAX) * 1024 ) + 1;
      cout<<r<<"   ";
   }
   return 0;
}
