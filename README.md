# PLT Patcher
Plugin for IDA Pro that uses ida python to patch plt sections when IDA fails to do so automatically.

Only supports ``ELF64`` binaries, where ``ELF32`` support could be easily added I don't have any binary of that sort to test on.

Additionaly this repository has ``thunk_type_preserver.py`` plugin that force preserves guessed type for thunks around extern functions.

## Installation
To install plugins from this repository, press ``Code -> Download ZIP`` to download python plugins, then extract ``.py`` files to ``IDA Folder/plugins``. Start\Restart IDA instance, then you should be able to see ``Edit->Plugins->Patch Plt Section`` button.

For ``thunk_type_preserver.py`` you don't need to press anything it should run automatically on the background, additionaly you might see double decompilations (especially noticable on big functions) which is expected behaviour and have an instance lifespan (so you'd see that again once IDA is restarted).

## Use cases
* ``plt_patcher.py`` - if you get IDA warning at analyzing step ``Could not patch the PLT stub; unexpected PLT format or the file has been modified after linking!``, this should help to patch PLT section correctly. Binaries compiled with [mold](https://github.com/rui314/mold) linker will most likely produce this error.

* ``thunk_type_preserver.py`` - useful in pseudocode static analysis as otherwise when you traverse to these thunk functions their args type info would be wiped if extern function doesn't have any type info (i.e. c style extern).

## IDA Support
* Requires IDA Pro for idapython;
* Tested on ida 7.7 and 9.0, versions in between should also work just fine, previous versions are unsupported!
* ``thunk_type_preserver.py`` also requires hexrays plugin to be installed;
