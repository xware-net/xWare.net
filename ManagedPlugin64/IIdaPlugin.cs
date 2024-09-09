using System;

namespace ManagedPlugin
{
    public interface IIdaPlugin
    {
        int Initialize();
        void Run(string name);
        void Terminate();
    }
}
