#include <iostream>
#include <cstring>
#include <cstdlib>

class N
{
private:
    char annotation[100];
    int value;

public:
    N(int val) : value(val)
    {
        memset(annotation, 0, sizeof(annotation));
    }

    virtual ~N() {}

    void setAnnotation(const char *str)
    {
        size_t len = strlen(str);
        memcpy(annotation, str, len);
    }

    virtual int operator+(const N &other)
    {
        return this->value + other.value;
    }

    int operator-(const N &other)
    {
        return this->value - other.value;
    }

    virtual void operator()(N *other)
    {
        int result = *this + *other;
        std::cout << "Result: " << result << std::endl;
    }

};

int main(int argc, char **argv)
{
    // Check if we have at least one command line argument
    if (argc < 2)
        exit(1);
    // Create two N objects
    N *obj1 = new N(5);
    N *obj2 = new N(6);
    // Set annotation from command line argument
    obj1->setAnnotation(argv[1]);
    // Call the function operator (virtual function call through vtable)
    (*obj1)(obj1);
    return 0;
}