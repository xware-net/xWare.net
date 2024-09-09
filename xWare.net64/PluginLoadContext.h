#pragma once
//#include <xkeycheck.h>

using namespace System;
using namespace System::IO;
using namespace System::Reflection;
using namespace System::Runtime::Loader;
using namespace System::Collections;

public ref class PluginLoadContext : public AssemblyLoadContext
{
private:
	AssemblyDependencyResolver^ _resolver;

public:
	PluginLoadContext(String^ pluginPath)
	{
		_resolver = gcnew AssemblyDependencyResolver(pluginPath);
	}

protected:
	Assembly^ Load(AssemblyName^ assemblyName) override
	{
		String^ assemblyPath = _resolver->ResolveAssemblyToPath(assemblyName);
		if (assemblyPath != nullptr)
		{
			return LoadFromAssemblyPath(assemblyPath);
		}

		return nullptr;
	}

	IntPtr LoadUnmanagedDll(String^ unmanagedDllName) override
	{
		String^ libraryPath = _resolver->ResolveUnmanagedDllToPath(unmanagedDllName);
		if (libraryPath != nullptr)
		{
			return LoadUnmanagedDllFromPath(libraryPath);
		}

		return IntPtr::Zero;
	}
};