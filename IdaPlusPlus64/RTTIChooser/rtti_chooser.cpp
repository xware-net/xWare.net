#include "rtti_chooser.h"

#define STYLE_PATH ":/classinf/"

const UINT CHD_MULTINH = 0x01;    // Multiple inheritance
const UINT CHD_VIRTINH = 0x02;    // Virtual inheritance
const UINT CHD_AMBIGUOUS = 0x04;    // Ambiguous inheritance
const WORD IS_TOP_LEVEL = 0x8000;

#define GRAY(v) RGB(v,v,v)
static const bgcolor_t NOT_PARENT_COLOR = GRAY(235);

#define MY_VERSION MAKEWORD(7, 2) // Low, high, convention: 0 to 99

// Netnode constants
const static char NETNODE_NAME[] = { "$ClassInformer_node" };
const char NN_DATA_TAG = 'A';
const char NN_TABLE_TAG = 'S';

// Our netnode value indexes
enum NETINDX
{
	NIDX_VERSION,   // ClassInformer version
	NIDX_COUNT      // Table entry count
};

// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{
	ea_t vft;
	WORD methods;
	WORD flags;
	WORD strSize;
	char str[MAXSPECSIZE - (sizeof(ea_t) + (sizeof(WORD) * 3))]{}; // Note: IDA MAXSTR = 1024

	inline static auto offsetof_str() { return sizeof(ea_t) + sizeof(WORD) + sizeof(WORD) + sizeof(WORD); }
};
#pragma pack(pop)

static netnode *getOrCreate()
{
	netnode* net_node = nullptr;

	// look if we have a storage netnode
	// Create new storage netnode
	if (net_node = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), TRUE))
	{
		return net_node;
	}

	return nullptr;
}

static netnode* netNode = getOrCreate();

static void freeWorkingData()
{
	try
	{
		//if (netNode)
		//{
		//	delete netNode;
		//	netNode = NULL;
		//}
	}
	catch (...)
	{
	}
}

static UINT getTableCount() { return(netNode->altval_idx8(NIDX_COUNT, NN_DATA_TAG)); }
static BOOL setTableCount(UINT count) { return(netNode->altset_idx8(NIDX_COUNT, count, NN_DATA_TAG)); }
static BOOL getTableEntry(TBLENTRY& entry, UINT index) { return(netNode->supval(index, &entry, sizeof(TBLENTRY), NN_TABLE_TAG) > 0); }
static BOOL setTableEntry(TBLENTRY& entry, UINT index) { return(netNode->supset(index, &entry, (TBLENTRY::offsetof_str() + entry.strSize), NN_TABLE_TAG)); }

// Add an entry to the vftable list
void rtti_chooser::addTableEntry(ea_t vft, WORD methodCount, WORD flags, const char* format, ...)
{
	TBLENTRY e;
	e.vft = vft;
	e.methods = methodCount;
	e.flags = flags;

	va_list vl;
	va_start(vl, format);
	auto written = vsnprintf_s(e.str, sizeof(e.str), SIZESTR(e.str), format, vl);
	va_end(vl);
	e.strSize += written;

	UINT count = getTableCount();
	setTableEntry(e, count);
	setTableCount(++count);
}

// find_widget
static QWidget* findChildByClass(QWidgetList& wl, LPCSTR className)
{
	foreach(QWidget * w, wl)
		if (strcmp(w->metaObject()->className(), className) == 0)
			return(w);
	return nullptr;
}

void rtti_chooser::customizeChooserWindow()
{
	try
	{
		QApplication::processEvents();

		// Get parent chooser dock widget
		QWidgetList pl = QApplication::activeWindow()->findChildren<QWidget*>("[Class Informer]");
		if (QWidget* dw = findChildByClass(pl, "IDADockWidget"))
		{
			QFile file(STYLE_PATH "view-style.qss");
			if (file.open(QFile::ReadOnly | QFile::Text))
				dw->setStyleSheet(QTextStream(&file).readAll());
		}
		else
			msg("** customizeChooseWindow(): \"IDADockWidget\" not found!\n");

		// Get chooser widget
		if (QTableView* tv = (QTableView*)findChildByClass(pl, "TChooserView"))
		{
			// Set sort by type name
			tv->sortByColumn(3, Qt::DescendingOrder);

			// Resize to contents
			tv->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
			tv->resizeColumnsToContents();
			tv->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

			UINT count = getTableCount();
			for (UINT row = 0; row < count; row++)
				tv->setRowHeight(row, 24);
		}
		else
			msg("** customizeChooseWindow(): \"TChooserView\" not found!\n");
	}
	catch (...)
	{
	}
}

// Init new netnode storage
static void newNetnodeStore()
{
	// Kill any existing store data first
	netNode->altdel_all(NN_DATA_TAG);
	netNode->supdel_all(NN_TABLE_TAG);

	// Init defaults
	netNode->altset_idx8(NIDX_VERSION, MY_VERSION, NN_DATA_TAG);
	netNode->altset_idx8(NIDX_COUNT, 0, NN_DATA_TAG);
}

rtti_chooser::rtti_chooser() : chooser_multi_t(CH_QFTYP_DEFAULT, LBCOLUMNCOUNT, LBWIDTHS, LBHEADER, LBTITLE)
{
	// Setup hex address display to the minimal size needed plus a leading zero
	UINT count = getTableCount();
	ea_t largestAddres = 0;
	for (UINT i = 0; i < count; i++)
	{
		TBLENTRY e; e.vft = 0;
		getTableEntry(e, i);
		if (e.vft > largestAddres)
			largestAddres = e.vft;
	}

	char buffer[32];
	int digits = (int)strlen(_ui64toa(largestAddres, buffer, 16));
	if (++digits > 16) digits = 16;
	sprintf_s(addressFormat, sizeof(addressFormat), "%%0%uI64X", digits);

	// Chooser icon
	icon = chooserIcon;
}

const void* rtti_chooser::get_obj_id(size_t* len) const
{
	*len = sizeof(LBTITLE);
	return LBTITLE;
}

size_t rtti_chooser::get_count() const { return (size_t)getTableCount(); }

void rtti_chooser::get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attributes, size_t n) const
{
	try
	{
		if (netNode)
		{
			// Generate the line
			TBLENTRY e;
			getTableEntry(e, (UINT)n);
			//msg("--> row %ld, %16llX, %ld, %ld, %s\n", n, e.vft, e.methods, e.flags, e.str);

			// vft address
			qstrvec_t& cols = *cols_;
			cols[0].sprnt(addressFormat, e.vft);

			// Method count
			if (e.methods > 0)
				cols[1].sprnt("%u", e.methods); // "%04u"
			else
				cols[1].sprnt("???");

			// Flags
			char flags[4];
			int pos = 0;
			if (e.flags & CHD_MULTINH)   flags[pos++] = 'M';
			if (e.flags & CHD_VIRTINH)   flags[pos++] = 'V';
			if (e.flags & CHD_AMBIGUOUS) flags[pos++] = 'A';
			flags[pos++] = 0;
			cols[2] = flags;

			// Type
			LPCSTR tag = strchr(e.str, '@');
			if (tag)
			{
				char buffer[MAXSTR]{};
				auto lastidx = SIZESTR(buffer);
				int pos = (tag - e.str);
				if (pos > lastidx)
					pos = lastidx;
				std::memcpy(buffer, e.str, pos);
				buffer[pos] = 0;
				cols[3] = qstring(buffer);
				++tag;
			}
			else
			{
				// Can happen when string is MAXSTR and greater
				cols[3] = "??** MAXSTR overflow!";
				tag = e.str;
			}

			// Composition/hierarchy
			cols[4] = qstring(tag);

			//*icon_ = ((e.flags & RTTI::IS_TOP_LEVEL) ? 77 : 191);
			*icon_ = 191;

			// Indicate entry is not a top/parent level by color
			if (!(e.flags & IS_TOP_LEVEL))
				attributes->color = NOT_PARENT_COLOR;
		}
	}
	catch(...)
	{
	}
}

chooser_base_t::cbres_t rtti_chooser::enter(sizevec_t* sel)
{
	size_t n = sel->front();
	if (n < get_count())
	{
		TBLENTRY e;
		getTableEntry(e, (UINT)n);
		jumpto(e.vft);
	}

	return NOTHING_CHANGED;
}

void rtti_chooser::closed()
{
	freeWorkingData();
}
