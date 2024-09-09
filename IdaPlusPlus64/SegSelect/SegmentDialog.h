#pragma once

#include <Windows.h>

#include <QtWidgets/QDialog>
#include "ui_SegmentDialog.h"

#define USE_DANGEROUS_FUNCTIONS
#include <ida.hpp>
#include <idp.hpp>
#include "segment.hpp"

#include "SegSelectEx.h"

typedef std::vector<segment_t*> SegSelectEx_segments;

class SegmentDialog : public QDialog, public Ui::SegSelectDialog
{
    Q_OBJECT
public:
    SegmentDialog(QWidget *parent, UINT flags, LPCSTR title, LPCSTR styleSheet, LPCSTR icon);
	virtual ~SegmentDialog() { Q_CLEANUP_RESOURCE(SegSelectRes);  }
    void saveGeometry() { geom = geometry(); }
    SegSelectEx_segments *getSelected();

private:
    static QRect geom;

private slots:
    void onDoubleRowClick(int row, int column);
};


