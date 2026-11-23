unsigned demo_transform(unsigned value)
{
    if (value == 0)
        return 7u;
    return value ^ 21u;
}

int main(void)
{
    return demo_transform(0u) != 7u || demo_transform(4u) != 17u;
}
