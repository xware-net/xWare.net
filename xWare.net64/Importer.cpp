#include "pch.h"
#include "Importer.hpp"
#include "PluginLoadContext.h"

#pragma managed
Assembly^ LoadPlugin(String^ pluginPath)
{
	PluginLoadContext^ loadContext = gcnew PluginLoadContext(pluginPath);
	return loadContext->LoadFromAssemblyName(gcnew AssemblyName(Path::GetFileNameWithoutExtension(pluginPath)));
}

System::Object^ CreateAndInitializeIdaPlugin(Assembly^ assembly, System::Type^% type)
{
	auto types = assembly->GetTypes();
	IEnumerator^ typeIter = types->GetEnumerator();
	while (typeIter->MoveNext())
	{
		Type^ t = dynamic_cast<Type^>(typeIter->Current);
		if (t->Name == "Plugin")
		{
			auto result = Activator::CreateInstance(t);
			if (result != nullptr)
			{
				type = t;
				return result;
			}
		}
	}

	return nullptr;
}

bool runPlugin(char* name)
{
	String^ idaDir = Environment::GetEnvironmentVariable("IDADIR");
	String^ pluginLocation = Path::Combine(idaDir, "plugins/MixedModePlugin64/ManagedPlugin64.dll");
	pluginLocation = pluginLocation->Replace("\\", "/");
	Assembly^ assembly = LoadPlugin(pluginLocation);
	Type^ pluginType;
	auto plugin = CreateAndInitializeIdaPlugin(assembly, pluginType);
	if (plugin != nullptr)
	{
		array<MethodInfo^>^ methods = pluginType->GetMethods();
		IEnumerator^ methodIter = methods->GetEnumerator();
		while (methodIter->MoveNext())
		{
			MethodInfo^ mi = dynamic_cast<MethodInfo^>(methodIter->Current);
			if (mi->Name == "Run")
			{
				mi->Invoke(plugin, gcnew array<Object^>{ gcnew String(name) });
			}
		}
	}

	return true;
}

bool initPlugin()
{
	return true;
}

