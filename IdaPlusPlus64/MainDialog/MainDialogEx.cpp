
// ****************************************************************************
// File: MainDialog.cpp
// Desc: Main Dialog
//
// ****************************************************************************

#include "MainDialogEx.h"

#define STYLE_PATH ":/classinf/"

MainDialog::MainDialog(bool& optionPlaceStructs, bool& optionProcessStatic, bool& optionAudioOnDone) : QDialog(QApplication::activeWindow(), 0)
{
    Ui::MainCIDialog::setupUi(this);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    buttonBox->addButton("CONTINUE", QDialogButtonBox::AcceptRole);
    buttonBox->addButton("CANCEL", QDialogButtonBox::RejectRole);

    #define INITSTATE(obj,state) obj->setCheckState((state == TRUE) ? Qt::Checked : Qt::Unchecked);
    INITSTATE(checkBox1, optionPlaceStructs);
    INITSTATE(checkBox2, optionProcessStatic);
    INITSTATE(checkBox3, optionAudioOnDone);
    #undef INITSTATE

    // Apply style sheet
    QFile file(STYLE_PATH "style.qss");
    if (file.open(QFile::ReadOnly | QFile::Text))
        setStyleSheet(QTextStream(&file).readAll());
}

// On choose segments
void MainDialog::segmentSelect()
{
    SegSelectEx_select((DATA_HINT | RDATA_HINT), "Choose segments to scan");
}

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(bool& optionPlaceStructs, bool& optionProcessStatic, bool& optionAudioOnDone)
{
	BOOL result = TRUE;
    MainDialog *dlg = new MainDialog(optionPlaceStructs, optionProcessStatic, optionAudioOnDone);
    if (dlg->exec())
    {
        #define CHECKSTATE(obj,var) var = dlg->obj->isChecked()
        CHECKSTATE(checkBox1, optionPlaceStructs);
        CHECKSTATE(checkBox2, optionProcessStatic);
        CHECKSTATE(checkBox3, optionAudioOnDone);
        #undef CHECKSTATE
		result = FALSE;
    }
	delete dlg;
    return(result);
}