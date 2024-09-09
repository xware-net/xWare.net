#pragma once

#define STYLE_PATH ":/classinf/"

static void OggPlayer_EndPlay()
{
	OggPlay::endPlay();
}

static void OggPlayer_Play()
{
    QFile file(STYLE_PATH "completed.ogg");
    if (file.open(QFile::ReadOnly))
    {
        QByteArray ba = file.readAll();
        OggPlay::playFromMemory((const PVOID)ba.constData(), ba.size(), TRUE);
    }
}