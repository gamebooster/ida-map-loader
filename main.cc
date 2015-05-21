#include <string>

#include "Map.h"
#include "WaitBoxEx.h"

const char* plugin_name = "ida-map-loader";

int idaapi init(void)
{
	return PLUGIN_OK;
}

void idaapi run(int)
{
	msg("%s start\n", plugin_name);

	char input_file[MAXSTR];

	ssize_t len = get_input_file_path(input_file, sizeof(input_file));
	if (len == -1) {
		msg("ida-map-loader: ERROR: Could not get the path of the input file.\n");
		return;
	}

	if (len > sizeof(input_file)) {
		msg("ida-map-loader: ERROR: Input file name too long.\n");
		return;
	}

	std::string input_map_file = input_file;
	input_map_file.replace(input_map_file.find("exe"), 3, "map");

	msg("ida-map-loader: Opening map file '%s'\n", input_map_file.c_str());

	// Parse the map
	MapFile map;

	if (!map.Load(input_map_file.c_str())) {
		return;
	}

	ea_t image_base = get_segm_by_name(".text")->startEA;

	WaitBox::show();

	uint64 counter = 0;
	uint64 total_count = map.GetSymbols().size();
	int last_progress = 0;

	WaitBox::updateAndCancelCheck(0);

	for (auto& sym : map.GetSymbols()) {
		if (set_name(image_base + sym.Offset, sym.Name, SN_NOCHECK | SN_NOWARN) == false) {
			msg("0x%llx: WARNING: Failed to set name %s\n", image_base + sym.Offset, sym.Name);
		}
		counter++;

		int progress = ((double)counter / total_count) * 100;

		if ((progress - last_progress) == 1) {
			last_progress = progress;
			if (WaitBox::updateAndCancelCheck(progress)) {
				// Bail out on cancel
				msg("ida-map-loader: map renaming canceled *\n");
				WaitBox::processIdaEvents();
				break;
			}
		}
	}

	WaitBox::hide();

	msg("ida-map-loader: Applied %d symbol(s)\n", counter);
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL,           // plugin flags
	init,                 // initialize
	NULL,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	NULL,                 // long comment about the plugin
	NULL,                 // multiline help about the plugin
	"ida-map-loader",       // the preferred short name of the plugin
	NULL                  // the preferred hotkey to run the plugin
};
