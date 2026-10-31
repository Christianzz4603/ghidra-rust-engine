use std::io::Write;
use std::time::Instant;

use crate::action::{BREAK_ACTION, BREAK_START, STATUS_END, STATUS_START};
use crate::address::Address;
use crate::architecture::Architecture;
use crate::database::SymbolId;
use crate::error::Error;
use crate::fspec::ProtoModel;
use crate::funcdata::Funcdata;
use crate::graph::{dump_controlflow_graph, dump_dataflow_graph, dump_dom_graph};
use crate::intelligence::BinaryIntelligence;
use crate::interface::{IStream, IfaceError, IfaceResult, IfaceStatus, OutStream, out_write};
use crate::paramid::ParamIdAnalysis;
use crate::program::Program;
use crate::space::SpaceType;
use crate::types::print_data;

use super::load::read_machaddr;
use super::{
    IfaceAssemblyEmit, conf_mut, decomp_data, function_name, iterate_functions_addr_order,
    iterate_functions_leaf_order, symbol_table, with_current_action, with_current_function, with_function,
    with_printer,
};

fn no_function(message: &str) -> IfaceError {
    IfaceError::Execution(message.to_string())
}

fn decompiler_output_dir() -> IfaceResult<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("GHIDRA_DECOMPILER_OUTPUT_DIR") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path)
            .map_err(|err| IfaceError::Execution(format!("Cannot create output folder {}: {err}", path.display())))?;
        return Ok(path);
    }

    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        let path = directory.join("output");
        if std::fs::create_dir_all(&path).is_ok() {
            return Ok(path);
        }
    }

    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| IfaceError::Execution("Cannot determine a writable output directory".to_string()))?;
    let path = home.join(".local").join("share").join("ghidra-engine").join("output");
    std::fs::create_dir_all(&path).map_err(|err| {
        IfaceError::Execution(format!(
            "Cannot create fallback output folder {}: {err}",
            path.display()
        ))
    })?;
    Ok(path)
}

pub fn ifc_printdisasm(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    args.ws();
    let (mut addr, mut size) = if args.eof() {
        let Some(sym) = dcp.fd else {
            return Err(no_function("No function selected"));
        };
        let glb = conf_mut(dcp, "No function selected")?;
        let (name, addr, size) = with_function(glb, sym, |fd, _glb| {
            Ok((fd.get_name().to_string(), fd.get_address().clone(), fd.get_size()))
        })?;
        out_write(&fileoptr, &format!("Assembly listing for {name}\n"));
        (addr, size)
    } else {
        let glb = conf_mut(dcp, "No load image present")?;
        let mut size: i32 = 0;
        let addr = read_machaddr(args, &mut size, glb)?;
        args.ws();
        let offset2 = read_machaddr(args, &mut size, glb)?;
        let size = offset2.get_offset().wrapping_sub(addr.get_offset()) as i32;
        (addr, size)
    };
    let glb = conf_mut(dcp, "No load image present")?;
    let translate = glb
        .translate
        .as_deref()
        .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing translator".to_string())))?;
    let mut assem = IfaceAssemblyEmit::new(10);
    while size > 0 {
        let result = translate.print_assembly(&mut assem, &addr);
        out_write(&fileoptr, &std::mem::take(&mut assem.out));
        let sz = result?;
        addr = addr.add(sz as i64);
        size -= sz;
    }
    Ok(())
}

pub fn ifc_dump(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image present")?;
    let mut size: i32 = 0;
    let offset = read_machaddr(args, &mut size, glb)?;
    let loader = glb
        .loader
        .clone()
        .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing load image".to_string())))?;
    let buffer = loader.load(size, &offset)?;
    let mut text = String::new();
    print_data(&mut text, Some(&buffer), size, &offset);
    out_write(&fileoptr, &text);
    Ok(())
}

pub fn ifc_dumpbinary(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image present")?;
    let mut size: i32 = 0;
    let offset = read_machaddr(args, &mut size, glb)?;
    args.ws();
    if args.eof() {
        return Err(IfaceError::Parse("Missing file name for binary dump".to_string()));
    }
    let mut filename = String::new();
    args.read_word_into(&mut filename);
    let Ok(mut file) = std::fs::File::create(&filename) else {
        return Err(IfaceError::Execution(format!("Unable to open file {filename}")));
    };
    let loader = glb
        .loader
        .clone()
        .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing load image".to_string())))?;
    let buffer = loader.load(size, &offset)?;
    let _ = file.write_all(&buffer);
    Ok(())
}

fn perform_report(optr: &OutStream, res: i32, glb: &mut Architecture) {
    if res < 0 {
        out_write(optr, "Break at ");
        let mut state = String::new();
        if let Some(action) = glb.allacts.get_current() {
            action.print_state(&mut state);
        }
        out_write(optr, &state);
    } else {
        out_write(optr, "Decompilation complete");
        if res == 0 {
            out_write(optr, " (no change)");
        }
    }
    out_write(optr, "\n");
}

pub fn ifc_decompile(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let mut requested_name = String::new();
    args.ws();
    args.read_word_into(&mut requested_name);
    if requested_name.is_empty() {
        return Err(IfaceError::Parse("Usage: decompile <function>".to_string()));
    }

    if !requested_name.is_empty() {
        let dcp = decomp_data(status);
        let glb = conf_mut(dcp, "No image loaded")?;
        let delim = glb.get_scope_delimiter();
        let mut basename = String::new();
        let symboltab = symbol_table(glb)?;
        let Some(scope) = symboltab.resolve_scope_from_symbol_name(&requested_name, &delim, &mut basename, None) else {
            return Err(IfaceError::Execution(format!("Unknown function: {requested_name}")));
        };
        let Some(sym) = symboltab.scope_query_function_by_name(scope, &basename) else {
            return Err(IfaceError::Execution(format!("Unknown function: {requested_name}")));
        };
        dcp.fd = Some(sym);
        let glb = conf_mut(dcp, "No image loaded")?;
        let has_code = with_function(glb, sym, |fd, _glb| Ok(!fd.has_no_code()))?;
        if has_code {
            dcp.follow_flow(&optr, 0)?;
        }
    }

    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected. Use: decompile <function_name>"));
    }
    with_current_function(dcp, |fd, glb| {
        if fd.has_no_code() {
            out_write(&optr, &format!("No code for {}\n", fd.get_name()));
            return Ok(());
        }
        if fd.is_proc_started() {
            out_write(&optr, "Clearing old decompilation\n");
            glb.clear_analysis(fd);
        }
        let name = fd.get_name().to_string();
        out_write(&optr, &format!("Decompiling {name}...\n"));
        let res = with_current_action(glb, |action, glb| {
            action.reset(fd, glb);
            action.perform(fd, glb)
        })?;
        perform_report(&optr, res, glb);

        let ((), text) = with_printer(glb, Some(fd), |printer, ctx| printer.doc_function(ctx))?;
        let safe_name: String = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let safe_name = if safe_name.is_empty() { "function" } else { &safe_name };
        let output_dir = decompiler_output_dir()?;
        let output_path = output_dir.join(format!("{safe_name}.c"));
        std::fs::write(&output_path, &text).map_err(|err| {
            IfaceError::Execution(format!("Cannot save decompiled file {}: {err}", output_path.display()))
        })?;
        out_write(&optr, &format!("Saved C pseudocode to {}\n", output_path.display()));
        out_write(&optr, &text);
        Ok(())
    })
}

pub fn ifc_print_cflat(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let ((), text) = with_printer(glb, Some(fd), |printer, ctx| {
            printer.set_flat(true);
            let result = printer.doc_function(ctx);
            printer.set_flat(false);
            result
        })?;
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_cglobals(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image present")?;
    let ((), text) = with_printer(glb, None, |printer, ctx| printer.doc_all_globals(ctx))?;
    out_write(&fileoptr, &text);
    Ok(())
}

pub fn ifc_print_ctypes(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image present")?;
    if glb.types.is_some() {
        let ((), text) = with_printer(glb, None, |printer, ctx| printer.doc_type_definitions(ctx))?;
        out_write(&fileoptr, &text);
    }
    Ok(())
}

pub fn ifc_print_cxml(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let ((), text) = with_printer(glb, Some(fd), |printer, ctx| {
            printer.set_markup(true);
            printer.set_packed_output(false);
            let result = printer.doc_function(ctx);
            printer.get_output_stream().push(b'\n');
            printer.set_markup(false);
            result
        })?;
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_cstruct(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let ((), text) = with_printer(glb, Some(fd), |printer, ctx| printer.doc_function(ctx))?;
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_language(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    args.ws();
    if args.eof() {
        return Err(IfaceError::Parse("No print language specified".to_string()));
    }
    let mut langroot = String::new();
    args.read_word_into(&mut langroot);
    langroot.push_str("-language");
    with_current_function(dcp, |fd, glb| {
        let curlangname = glb.printlist[glb.print]
            .as_deref()
            .map(|printer| printer.get_name().to_string())
            .unwrap_or_default();
        glb.set_print_language(&langroot)?;
        let result = with_printer(glb, Some(fd), |printer, ctx| printer.doc_function(ctx));
        let reset = glb.set_print_language(&curlangname);
        let ((), text) = result?;
        reset?;
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_raw(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let mut text = String::new();
        let result = fd.print_raw(&mut text, glb);
        out_write(&fileoptr, &text);
        result?;
        Ok(())
    })
}

pub fn ifc_listaction(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "Decompile action not loaded")?;
    let mut text = String::new();
    if let Some(action) = glb.allacts.get_current() {
        action.print(&mut text, 0, 0);
    }
    out_write(&fileoptr, &text);
    Ok(())
}

pub fn ifc_list_override(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let mut text = format!("Function: {}\n", fd.get_name());
        let result = fd.get_override().print_raw(&mut text, glb);
        out_write(&optr, &text);
        result?;
        Ok(())
    })
}

pub fn ifc_listprototypes(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image present")?;
    let mut text = String::new();
    for model in glb.proto_model_map.values() {
        text.push_str(glb.proto_models.get(*model).get_name());
        if Some(*model) == glb.defaultfp {
            text.push_str(" default");
        } else if Some(*model) == glb.evalfp_called {
            text.push_str(" eval called");
        } else if Some(*model) == glb.evalfp_current {
            text.push_str(" eval current");
        }
        text.push('\n');
    }
    out_write(&optr, &text);
    Ok(())
}

fn set_break(args: &mut IStream, status: &mut IfaceStatus, tp: u32) -> IfaceResult<()> {
    let mut specify = String::new();
    args.read_word_into(&mut specify).ws();
    if specify.is_empty() {
        return Err(IfaceError::Execution("No action/rule specified".to_string()));
    }
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "Decompile action not loaded")?;
    let res = match glb.allacts.get_current() {
        Some(action) => action.set_break_point(tp, &specify),
        None => false,
    };
    if !res {
        return Err(IfaceError::Execution(format!("Bad action/rule specifier: {specify}")));
    }
    Ok(())
}

pub fn ifc_breakaction(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    set_break(args, status, BREAK_ACTION)
}

pub fn ifc_breakstart(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    set_break(args, status, BREAK_START)
}

pub fn ifc_print_tree(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let mut text = String::new();
        fd.print_varnode_tree(&mut text, glb);
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_blocktree(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let mut text = String::new();
        fd.print_block_tree(&mut text, glb);
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_spaces(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image present")?;
    let num = glb.manager.num_spaces();
    let mut text = String::new();
    for index in 0..num {
        let Some(spc) = glb.manager.get_space(index) else {
            continue;
        };
        text.push_str(&format!(
            "{} : '{}' {}",
            spc.get_index(),
            spc.get_shortcut(),
            spc.get_name()
        ));
        match spc.get_type() {
            SpaceType::Constant => text.push_str(" constant "),
            SpaceType::Processor => text.push_str(" processor"),
            SpaceType::Spacebase => text.push_str(" spacebase"),
            SpaceType::Internal => text.push_str(" internal "),
            _ => text.push_str(" special  "),
        }
        if spc.is_big_endian() {
            text.push_str(" big  ");
        } else {
            text.push_str(" small");
        }
        text.push_str(&format!(
            " addrsize={} wordsize={} delay={}\n",
            spc.get_addr_size(),
            spc.get_word_size(),
            spc.get_delay()
        ));
    }
    out_write(&fileoptr, &text);
    Ok(())
}

pub fn ifc_print_high(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    let mut varname = String::new();
    args.read_word_into(&mut varname).ws();
    with_current_function(dcp, |fd, glb| {
        let Some(high) = fd.find_high(&varname, glb)? else {
            return Err(IfaceError::Execution(format!("Unknown variable name: {varname}")));
        };
        let mut text = String::new();
        fd.high_print_info(high, &mut text, glb);
        out_write(&optr, &text);
        Ok(())
    })
}

pub fn ifc_print_param_measures(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let pidanalysis = ParamIdAnalysis::new(fd, false, glb);
        let mut text = String::new();
        pidanalysis.save_pretty(&mut text, true, fd, glb);
        text.push('\n');
        out_write(&fileoptr, &text);
        Ok(())
    })
}

pub fn ifc_print_localrange(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, glb| {
        let mut text = String::new();
        fd.print_local_range(&mut text, glb);
        out_write(&optr, &text);
        Ok(())
    })
}

pub fn ifc_print_map(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let mut name = String::new();
    args.read_word_into(&mut name);
    let dcp = decomp_data(status);
    let fdsym = dcp.fd;
    let glb = conf_mut(dcp, "No load image")?;
    let scope = if !name.is_empty() || fdsym.is_none() {
        let mut fullname = format!("{name}::a");
        let delim = glb.get_scope_delimiter();
        let lookup = fullname.clone();
        symbol_table(glb)?.resolve_scope_from_symbol_name(&lookup, &delim, &mut fullname, None)
    } else {
        let sym = fdsym.expect("function is selected");
        with_function(glb, sym, |fd, _glb| Ok(fd.get_scope_local()))?
    };
    let Some(scope) = scope else {
        return Err(IfaceError::Execution(format!("No map named: {name}")));
    };
    let delim = glb.get_scope_delimiter();
    let types = glb
        .types
        .as_deref()
        .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing type factory".to_string())))?;
    let symboltab = glb
        .symboltab
        .as_deref()
        .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing symbol table".to_string())))?;
    let mut text = symboltab.scope_get_full_name(scope, &delim);
    text.push('\n');
    symboltab.scope(scope).print_bounds(&mut text);
    symboltab.scope_print_entries(scope, &mut text, types);
    out_write(&fileoptr, &text);
    Ok(())
}

fn timed_perform(fd: &mut Funcdata, glb: &mut Architecture) -> crate::error::Result<f32> {
    glb.clear_analysis(fd);
    let start = Instant::now();
    with_current_action(glb, |action, glb| {
        action.reset(fd, glb);
        action.perform(fd, glb)
    })?;
    Ok(start.elapsed().as_secs_f32() * 1000.0)
}

pub fn ifc_produce_c(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let mut name = String::new();
    args.ws().read_word_into(&mut name);
    if name.is_empty() {
        return Err(IfaceError::Parse("Need file name to write to".to_string()));
    }
    let mut output = String::new();
    let mut callback = |status: &mut IfaceStatus, sym: SymbolId| -> IfaceResult<()> {
        let glb = conf_mut(decomp_data(status), "No architecture loaded")?;
        with_function(glb, sym, |fd, glb| {
            if fd.has_no_code() {
                out_write(&optr, &format!("No code for {}\n", fd.get_name()));
                return Ok(());
            }
            let result = timed_perform(fd, glb).and_then(|duration| {
                out_write(
                    &optr,
                    &format!(
                        "Decompiled {}({}) time={:.0} ms\n",
                        fd.get_name(),
                        fd.get_size(),
                        duration
                    ),
                );
                let ((), text) = with_printer(glb, Some(fd), |printer, ctx| printer.doc_function(ctx))?;
                output.push_str(&text);
                Ok(())
            });
            if let Err(err) = result {
                if !err.is_lowlevel() {
                    return Err(err.into());
                }
                out_write(&optr, &format!("Skipping {}: {}\n", fd.get_name(), err.explain()));
            }
            glb.clear_analysis(fd);
            Ok(())
        })
    };
    let result = iterate_functions_addr_order(status, &mut callback);
    if let Ok(mut file) = std::fs::File::create(&name) {
        let _ = file.write_all(output.as_bytes());
    }
    result
}

pub fn ifc_analyze_all(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let mut output_dir = String::new();
    args.ws().read_word_into(&mut output_dir);
    if output_dir.is_empty() {
        output_dir =
            std::env::var("GHIDRA_DECOMPILER_OUTPUT_DIR").unwrap_or_else(|_| "/sdcard/home/analysis".to_string());
    }
    let directory = std::path::Path::new(&output_dir);
    std::fs::create_dir_all(directory).map_err(|err| {
        IfaceError::Execution(format!("Cannot create analysis folder {}: {err}", directory.display()))
    })?;
    let filename = {
        let dcp = decomp_data(status);
        let glb = conf_mut(dcp, "No architecture loaded")?;
        glb.loader
            .as_ref()
            .ok_or_else(|| IfaceError::Execution("No load image present".to_string()))?
            .get_file_name()
            .to_string()
    };
    let binary_name = std::path::Path::new(&filename)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("binary");
    let c_path = directory.join(format!("{binary_name}.c"));
    let asm_path = directory.join(format!("{binary_name}.asm"));
    let csv_path = directory.join(format!("{binary_name}.csv"));
    let report_path = directory.join(format!("{binary_name}.report.txt"));
    let mut c_file = std::fs::File::create(&c_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", c_path.display())))?;
    let mut asm_file = std::fs::File::create(&asm_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", asm_path.display())))?;
    let mut csv_file = std::fs::File::create(&csv_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", csv_path.display())))?;

    out_write(&optr, &format!("Loading program metadata for {filename}...\n"));
    let mut program = Program::open(std::path::Path::new(&filename), None)
        .map_err(|err| IfaceError::Execution(format!("Cannot open program for discovery: {}", err.explain())))?;
    out_write(
        &optr,
        "Discovering functions from entry point, symbols, and reachable code...\n",
    );
    program
        .discover_functions()
        .map_err(|err| IfaceError::Execution(format!("Function discovery failed: {}", err.explain())))?;
    let functions = program
        .functions()
        .map_err(|err| IfaceError::Execution(format!("Cannot list functions: {}", err.explain())))?;
    let data = program
        .data_symbols()
        .map_err(|err| IfaceError::Execution(format!("Cannot list data symbols: {}", err.explain())))?;
    let strings = program
        .strings()
        .map_err(|err| IfaceError::Execution(format!("Cannot extract strings: {}", err.explain())))?;
    let calls = program
        .call_graph()
        .map_err(|err| IfaceError::Execution(format!("Cannot build call graph: {}", err.explain())))?;
    let csv = |value: &str| format!("\"{}\"", value.replace('\"', "\"\""));
    let coverage_path = directory.join(format!("{binary_name}.coverage.csv"));
    let mut coverage_file = std::fs::File::create(&coverage_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", coverage_path.display())))?;
    writeln!(
        coverage_file,
        "record,section_start,section_end,address,bytes,decoded_bytes,instructions,gaps"
    )
    .map_err(|err| IfaceError::Execution(err.to_string()))?;
    let code_coverage = program
        .scan_code_sections(|gap| {
            writeln!(coverage_file, "gap,,,{:#x},{},,,", gap.address, gap.length)
                .map_err(|err| Error::Lowlevel(err.to_string()))
        })
        .map_err(|err| IfaceError::Execution(format!("Executable-section sweep failed: {}", err.explain())))?;
    for section in &code_coverage.sections {
        writeln!(
            coverage_file,
            "section,{:#x},{:#x},,{},{},{},{}",
            section.start,
            section.end,
            section.requested_bytes,
            section.decoded_bytes,
            section.instruction_count,
            section.gap_count
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }
    coverage_file
        .flush()
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    let intelligence = BinaryIntelligence::new(&mut program)
        .analyze_all()
        .map_err(|err| IfaceError::Execution(format!("Intelligence analysis failed: {}", err.explain())))?;

    let xrefs_path = directory.join(format!("{binary_name}.xrefs.csv"));
    let cfg_path = directory.join(format!("{binary_name}.cfg.csv"));
    let dataflow_path = directory.join(format!("{binary_name}.dataflow.csv"));
    let fingerprints_path = directory.join(format!("{binary_name}.fingerprints.csv"));
    let prototypes_path = directory.join(format!("{binary_name}.prototypes.csv"));
    let intelligence_failures_path = directory.join(format!("{binary_name}.intelligence-failures.csv"));

    let mut xrefs_file = std::fs::File::create(&xrefs_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", xrefs_path.display())))?;
    let mut cfg_file = std::fs::File::create(&cfg_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", cfg_path.display())))?;
    let mut dataflow_file = std::fs::File::create(&dataflow_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", dataflow_path.display())))?;
    let mut fingerprints_file = std::fs::File::create(&fingerprints_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", fingerprints_path.display())))?;
    let mut prototypes_file = std::fs::File::create(&prototypes_path)
        .map_err(|err| IfaceError::Execution(format!("Cannot create {}: {err}", prototypes_path.display())))?;
    let mut intelligence_failures_file = std::fs::File::create(&intelligence_failures_path).map_err(|err| {
        IfaceError::Execution(format!("Cannot create {}: {err}", intelligence_failures_path.display()))
    })?;

    writeln!(xrefs_file, "from,to,kind,function,confidence").map_err(|err| IfaceError::Execution(err.to_string()))?;
    for reference in &intelligence.cross_references {
        writeln!(
            xrefs_file,
            "{:#x},{:#x},{:?},{},{:?}",
            reference.from,
            reference.to,
            reference.kind,
            reference
                .function
                .map(|value| format!("{value:#x}"))
                .unwrap_or_default(),
            reference.confidence
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }

    writeln!(
        cfg_file,
        "function,block_start,block_end,instruction_count,edge_from,edge_to,edge_kind,confidence"
    )
    .map_err(|err| IfaceError::Execution(err.to_string()))?;
    for graph in &intelligence.control_flow_graphs {
        let mut edges_by_block: std::collections::HashMap<u64, Vec<&crate::intelligence::FlowEdge>> = std::collections::HashMap::new();
        for edge in &graph.edges {
            edges_by_block.entry(edge.from).or_default().push(edge);
        }
        for block in &graph.blocks {
            let edges = edges_by_block.get(&block.start).map(Vec::as_slice).unwrap_or(&[]);
            if edges.is_empty() {
                writeln!(
                    cfg_file,
                    "{:#x},{:#x},{:#x},{},,,,",
                    graph.function,
                    block.start,
                    block.end,
                    block.instructions.len()
                )
                .map_err(|err| IfaceError::Execution(err.to_string()))?;
            } else {
                for edge in edges {
                    writeln!(
                        cfg_file,
                        "{:#x},{:#x},{:#x},{},{:#x},{},{:?},{:?}",
                        graph.function,
                        block.start,
                        block.end,
                        block.instructions.len(),
                        edge.from,
                        edge.to.map(|value| format!("{value:#x}")).unwrap_or_default(),
                        edge.kind,
                        edge.confidence
                    )
                    .map_err(|err| IfaceError::Execution(err.to_string()))?;
                }
            }
        }
    }

    writeln!(dataflow_file, "function,instructions,pcode_operations,definitions,memory_reads,memory_writes,calls,branches,returns,constant_count,type_widths")
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    for (index, summary) in intelligence.data_flow.iter().enumerate() {
        let function = intelligence
            .control_flow_graphs
            .get(index)
            .map(|graph| graph.function)
            .unwrap_or(0);
        let widths = summary
            .type_evidence
            .iter()
            .map(|item| item.storage_size.to_string())
            .collect::<Vec<_>>()
            .join(";");
        writeln!(
            dataflow_file,
            "{:#x},{},{},{},{},{},{},{},{},{},{}",
            function,
            summary.instruction_count,
            summary.operation_count,
            summary.definitions,
            summary.memory_reads,
            summary.memory_writes,
            summary.calls,
            summary.branches,
            summary.returns,
            summary.constants.len(),
            csv(&widths)
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }

    writeln!(
        fingerprints_file,
        "address,name,instructions,pcode_operations,byte_hash,opcode_histogram"
    )
    .map_err(|err| IfaceError::Execution(err.to_string()))?;
    for fingerprint in &intelligence.fingerprints {
        let histogram = fingerprint
            .opcode_histogram
            .iter()
            .map(|(opcode, count)| format!("{opcode}:{count}"))
            .collect::<Vec<_>>()
            .join(";");
        writeln!(
            fingerprints_file,
            "{:#x},{},{},{},{:#x},{}",
            fingerprint.address,
            csv(&fingerprint.name),
            fingerprint.instruction_count,
            fingerprint.operation_count,
            fingerprint.byte_hash,
            csv(&histogram)
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }

    writeln!(
        prototypes_file,
        "address,name,confidence,parameter_registers,return_size_evidence,notes"
    )
    .map_err(|err| IfaceError::Execution(err.to_string()))?;
    for prototype in &intelligence.prototypes {
        let registers = prototype.parameter_registers.join(";");
        let return_sizes = prototype
            .return_size_evidence
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(";");
        let notes = prototype.notes.join(" | ");
        writeln!(
            prototypes_file,
            "{:#x},{},{:?},{},{},{}",
            prototype.address,
            csv(&prototype.name),
            prototype.confidence,
            csv(&registers),
            csv(&return_sizes),
            csv(&notes)
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }

    writeln!(intelligence_failures_file, "address,name,stage,message")
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    for failure in &intelligence.failures {
        writeln!(
            intelligence_failures_file,
            "{:#x},{},{},{}",
            failure.address,
            csv(&failure.name),
            csv(&failure.stage),
            csv(&failure.message)
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }

    use std::io::Write as _;
    csv_file
        .write_all(b"type,name,address,size,details\n")
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    let names: std::collections::BTreeMap<u64, String> =
        functions.iter().map(|f| (f.address, f.name.clone())).collect();
    for function in &functions {
        writeln!(
            csv_file,
            "function,{},{:#x},,source={:?};symbol={}",
            csv(&function.name),
            function.address,
            function.source,
            csv(function.symbol.as_deref().unwrap_or(""))
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }
    for item in &data {
        writeln!(
            csv_file,
            "data,{},{:#x},{},symbol={}",
            csv(&item.name),
            item.address,
            item.size,
            csv(item.symbol.as_deref().unwrap_or(""))
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }
    for item in &strings {
        writeln!(
            csv_file,
            "string,{},,{},{:#x}",
            csv(&item.value),
            item.value.len(),
            item.address
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }
    for edge in &calls {
        let caller = names.get(&edge.caller).map(String::as_str).unwrap_or("unknown");
        let callee = names
            .get(&edge.callee)
            .map(String::as_str)
            .unwrap_or("external_or_unknown");
        writeln!(
            csv_file,
            "call,{} -> {},{:#x},,callee_address={:#x};call_site={:#x}",
            csv(caller),
            csv(callee),
            edge.caller,
            edge.callee,
            edge.call_site
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    }

    if functions.is_empty() {
        out_write(
            &optr,
            "No functions were discovered. The binary may have no usable entry point or function symbols. Data and strings were still exported.\n",
        );
    }
    let mut processed = 0usize;
    let mut skipped = 0usize;
    let mut assembly_ok = 0usize;
    let mut decompile_ok = 0usize;
    let mut size_failures = 0usize;
    let mut assembly_failures = 0usize;
    let mut decompile_failures = 0usize;
    let mut partial_disassemblies = 0usize;
    let mut undecoded_bytes = 0u64;
    let mut diagnostics = Vec::new();
    let total = functions.len();
    out_write(&optr, &format!("Analyzing {total} discovered function(s)...\n"));
    for function in functions {
        let name = function.name;
        let address = function.address;
        let size = match program.function_size(address) {
            Ok(size) if size > 0 => size,
            Ok(_) => {
                skipped += 1;
                size_failures += 1;
                diagnostics.push(format!("{name} @ {address:#x}: function size is zero"));
                writeln!(csv_file, "analysis_status,{},{:#x},,size=unknown", csv(&name), address)
                    .map_err(|err| IfaceError::Execution(err.to_string()))?;
                continue;
            }
            Err(err) => {
                skipped += 1;
                size_failures += 1;
                let message = err.explain();
                diagnostics.push(format!("{name} @ {address:#x}: size lookup failed: {message}"));
                writeln!(
                    csv_file,
                    "analysis_status,{},{:#x},,size_error={}",
                    csv(&name),
                    address,
                    csv(&message)
                )
                .map_err(|err| IfaceError::Execution(err.to_string()))?;
                out_write(&optr, &format!("Skipping {name}: {message}\n"));
                continue;
            }
        };
        let mut function_assembly_ok = false;
        let mut function_decompile_ok = false;
        let mut function_undecoded_bytes = 0u64;
        match program.disassemble_range_recovering(address, size) {
            Ok(report) => {
                writeln!(asm_file, "\n; {name} @ {address:#x}")
                    .map_err(|err| IfaceError::Execution(err.to_string()))?;
                if !report.instructions.is_empty() {
                    assembly_ok += 1;
                    function_assembly_ok = true;
                }
                if !report.gaps.is_empty() {
                    partial_disassemblies += 1;
                    let gap_bytes: u64 = report.gaps.iter().map(|gap| gap.length).sum();
                    undecoded_bytes += gap_bytes;
                    function_undecoded_bytes = gap_bytes;
                    diagnostics.push(format!(
                        "{name} @ {address:#x}: partial assembly; {gap_bytes} byte(s) undecoded"
                    ));
                    for gap in &report.gaps {
                        writeln!(asm_file, "{:#010x}: <undecoded {} byte(s)>", gap.address, gap.length)
                            .map_err(|err| IfaceError::Execution(err.to_string()))?;
                    }
                }
                for instruction in report.instructions {
                    let bytes = instruction
                        .bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    writeln!(
                        asm_file,
                        "{:#010x}: {:<24} {} {}",
                        instruction.address, bytes, instruction.mnemonic, instruction.operands
                    )
                    .map_err(|err| IfaceError::Execution(err.to_string()))?;
                }
            }
            Err(err) => {
                skipped += 1;
                assembly_failures += 1;
                let message = err.explain();
                diagnostics.push(format!("{name} @ {address:#x}: disassembly failed: {message}"));
                out_write(&optr, &format!("Assembly skipped for {name}: {message}\n"));
            }
        }
        match program.decompile(address) {
            Ok(text) => {
                writeln!(c_file, "\n/* {name} @ {address:#x} */")
                    .and_then(|_| c_file.write_all(text.as_bytes()))
                    .map_err(|err| IfaceError::Execution(err.to_string()))?;
                processed += 1;
                decompile_ok += 1;
                function_decompile_ok = true;
            }
            Err(err) => {
                skipped += 1;
                decompile_failures += 1;
                let message = err.explain();
                diagnostics.push(format!("{name} @ {address:#x}: decompilation failed: {message}"));
                out_write(&optr, &format!("Decompilation skipped for {name}: {message}\n"));
            }
        }
        writeln!(
            csv_file,
            "analysis_status,{},{:#x},{},assembly={};decompile={};undecoded_bytes={}",
            csv(&name),
            address,
            size,
            if function_assembly_ok { "ok" } else { "failed" },
            if function_decompile_ok { "ok" } else { "failed" },
            function_undecoded_bytes
        )
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
        if processed.is_multiple_of(25) && processed > 0 {
            out_write(&optr, &format!("Progress: {processed}/{total} functions processed\n"));
        }
    }
    c_file.flush().map_err(|err| IfaceError::Execution(err.to_string()))?;
    asm_file.flush().map_err(|err| IfaceError::Execution(err.to_string()))?;
    csv_file.flush().map_err(|err| IfaceError::Execution(err.to_string()))?;
    xrefs_file
        .flush()
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    cfg_file.flush().map_err(|err| IfaceError::Execution(err.to_string()))?;
    dataflow_file
        .flush()
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    fingerprints_file
        .flush()
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    prototypes_file
        .flush()
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    intelligence_failures_file
        .flush()
        .map_err(|err| IfaceError::Execution(err.to_string()))?;
    let report = format!(
        "GHIDRA-RUST-ENGINE ANALYSIS REPORT\n===============================\nInput file: {filename}\nDiscovered functions: {total}\nSuccessfully decompiled: {processed}\nFunctions with assembly exported: {assembly_ok}\nSize lookup failures: {size_failures}\nDisassembly failures: {assembly_failures}\nPartial disassemblies: {partial_disassemblies}\nUndecoded bytes in recovered function ranges: {undecoded_bytes}\nDecompilation failures: {decompile_failures}\nData symbols: {}\nStrings: {}\nCall edges: {}\nExecutable bytes scanned: {}\nExecutable bytes decoded: {}\nUndecoded executable bytes: {}\nSweep instructions: {}\nSweep gaps: {}\nCross references: {}\nCFGs recovered: {}\nData-flow summaries: {}\nFingerprints: {}\nPrototype evidence records: {}\nIntelligence failures: {}\n\nLIMITATIONS\n-----------\nFunction discovery is heuristic and may miss functions or include false positives. Assembly covers recovered function ranges only, not every executable byte. Decompiled C is inferred pseudocode, not original source or a guarantee of semantic equivalence. Xrefs, data references, function boundaries, names, and types may be incomplete. This engine does not claim IDA-equivalent completeness.\n\nDIAGNOSTICS\n-----------\n{}",
        data.len(),
        strings.len(),
        calls.len(),
        code_coverage.requested_bytes,
        code_coverage.decoded_bytes,
        code_coverage.undecoded_bytes,
        code_coverage.instruction_count,
        code_coverage.gap_count,
        intelligence.cross_references.len(),
        intelligence.control_flow_graphs.len(),
        intelligence.data_flow.len(),
        intelligence.fingerprints.len(),
        intelligence.prototypes.len(),
        intelligence.failures.len(),
        if diagnostics.is_empty() {
            "No per-function failures reported.".to_string()
        } else {
            diagnostics.join("\n")
        }
    );
    std::fs::write(&report_path, report)
        .map_err(|err| IfaceError::Execution(format!("Cannot write {}: {err}", report_path.display())))?;
    out_write(
        &optr,
        &format!(
            "\nAnalysis finished: {processed}/{total} functions decompiled; {skipped} operation(s) skipped.\nAssembly exported: {assembly_ok}/{total}. Failures: size={size_failures}, disassembly={assembly_failures}, decompilation={decompile_failures}.\nData symbols: {} | Strings: {} | Call edges: {}\nOutput folder: {}\nFiles: {binary_name}.c, {binary_name}.asm, {binary_name}.csv, {binary_name}.coverage.csv, {binary_name}.xrefs.csv, {binary_name}.cfg.csv, {binary_name}.dataflow.csv, {binary_name}.fingerprints.csv, {binary_name}.prototypes.csv, {binary_name}.intelligence-failures.csv, {binary_name}.report.txt\n",
            data.len(),
            strings.len(),
            calls.len(),
            directory.display()
        ),
    );
    Ok(())
}

pub fn ifc_produce_prototypes(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "No load image")?;
    let _ = glb;
    if dcp.cgraph.is_none() {
        return Err(IfaceError::Execution("Callgraph has not been built".to_string()));
    }
    let glb = conf_mut(dcp, "No load image")?;
    let Some(current) = glb.evalfp_current else {
        out_write(&optr, "Always using default prototype\n");
        return Ok(());
    };
    let model = glb.proto_models.get(current);
    if !model.is_merged() {
        out_write(&optr, &format!("Always using prototype {}\n", model.get_name()));
        return Ok(());
    }
    let mut text = String::from("Trying to distinguish between prototypes:\n");
    for index in 0..model.num_models() {
        let sub = model.get_model(index);
        text.push_str(&format!("  {}\n", glb.proto_models.get(sub).get_name()));
    }
    out_write(&optr, &text);
    let mut callback = |status: &mut IfaceStatus, sym: SymbolId| -> IfaceResult<()> {
        let glb = conf_mut(decomp_data(status), "No architecture loaded")?;
        with_function(glb, sym, |fd, glb| {
            out_write(&optr, &format!("{} ", fd.get_name()));
            if fd.has_no_code() {
                out_write(&optr, "has no code\n");
                return Ok(());
            }
            if fd.get_func_proto_mut().is_input_locked(glb) {
                out_write(&optr, "has locked prototype\n");
                return Ok(());
            }
            let result = timed_perform(fd, glb).map(|duration| {
                let modelname = fd.get_func_proto().get_model_name(glb).to_string();
                out_write(&optr, &format!("proto={modelname}"));
                fd.get_func_proto_mut().set_model_lock(true);
                out_write(&optr, &format!(" time={duration:.0} ms\n"));
            });
            if let Err(err) = result {
                if !err.is_lowlevel() {
                    return Err(err.into());
                }
                out_write(&optr, &format!("Skipping {}: {}\n", fd.get_name(), err.explain()));
            }
            glb.clear_analysis(fd);
            Ok(())
        })
    };
    iterate_functions_leaf_order(status, &mut callback)
}

pub fn ifc_continue(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    conf_mut(dcp, "Decompile action not loaded")?;
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    let glb = conf_mut(dcp, "Decompile action not loaded")?;
    let current_status = glb.allacts.get_current().map(|action| action.get_status());
    if current_status == Some(STATUS_START) {
        return Err(IfaceError::Execution("Decompilation has not been started".to_string()));
    }
    if current_status == Some(STATUS_END) {
        return Err(IfaceError::Execution("Decompilation is already complete".to_string()));
    }
    with_current_function(dcp, |fd, glb| {
        let res = with_current_action(glb, |action, glb| action.perform(fd, glb))?;
        perform_report(&optr, res, glb);
        Ok(())
    })
}

fn open_graph_file(args: &mut IStream) -> IfaceResult<String> {
    let mut filename = String::new();
    args.read_word_into(&mut filename);
    if filename.is_empty() {
        return Err(IfaceError::Parse("Missing output file".to_string()));
    }
    Ok(filename)
}

fn write_graph_file(filename: &str, text: &str) -> IfaceResult<()> {
    let Ok(mut file) = std::fs::File::create(filename) else {
        return Err(IfaceError::Execution(format!("Unable to open output file: {filename}")));
    };
    let _ = file.write_all(text.as_bytes());
    Ok(())
}

pub fn ifc_graph_dataflow(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    let filename = open_graph_file(args)?;
    with_current_function(dcp, |fd, glb| {
        if !fd.is_proc_started() {
            return Err(IfaceError::Execution("Syntax tree not calculated".to_string()));
        }
        if std::fs::File::create(&filename).is_err() {
            return Err(IfaceError::Execution(format!("Unable to open output file: {filename}")));
        }
        let mut text = String::new();
        dump_dataflow_graph(fd, &mut text, glb);
        write_graph_file(&filename, &text)
    })
}

pub fn ifc_graph_controlflow(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    let filename = open_graph_file(args)?;
    with_current_function(dcp, |fd, _glb| {
        let graph = fd.get_basic_blocks();
        if fd.block(graph).get_size() == 0 {
            return Err(IfaceError::Execution(
                "Basic block structure not calculated".to_string(),
            ));
        }
        if std::fs::File::create(&filename).is_err() {
            return Err(IfaceError::Execution(format!("Unable to open output file: {filename}")));
        }
        let mut text = String::new();
        let name = fd.get_name().to_string();
        dump_controlflow_graph(&name, fd, graph, &mut text);
        write_graph_file(&filename, &text)
    })
}

pub fn ifc_graph_dom(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let dcp = decomp_data(status);
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    let filename = open_graph_file(args)?;
    with_current_function(dcp, |fd, _glb| {
        if !fd.is_proc_started() {
            return Err(IfaceError::Execution(
                "Basic block structure not calculated".to_string(),
            ));
        }
        if std::fs::File::create(&filename).is_err() {
            return Err(IfaceError::Execution(format!("Unable to open output file: {filename}")));
        }
        let mut text = String::new();
        let name = fd.get_name().to_string();
        let graph = fd.get_basic_blocks();
        dump_dom_graph(&name, fd, graph, &mut text);
        write_graph_file(&filename, &text)
    })
}

pub fn ifc_comment_instr(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let dcp = decomp_data(status);
    conf_mut(dcp, "Decompile action not loaded")?;
    let Some(sym) = dcp.fd else {
        return Err(no_function("No function selected"));
    };
    let glb = conf_mut(dcp, "Decompile action not loaded")?;
    let mut size: i32 = 0;
    let addr = read_machaddr(args, &mut size, glb)?;
    args.ws();
    let mut comment = Vec::new();
    let mut tok = args.get();
    while !args.eof() {
        if let Some(byte) = tok {
            comment.push(byte);
        }
        tok = args.get();
    }
    let comment = String::from_utf8_lossy(&comment).into_owned();
    let tp = glb.printlist[glb.print]
        .as_deref()
        .map(|printer| printer.get_instruction_comment())
        .unwrap_or(0);
    let funcaddr = with_function(glb, sym, |fd, _glb| Ok(fd.get_address().clone()))?;
    glb.commentdb
        .as_deref_mut()
        .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing comment database".to_string())))?
        .add_comment(tp, &funcaddr, &addr, &comment);
    Ok(())
}

pub fn ifc_print_actionstats(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let fileoptr = status.fileoptr.clone();
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "Image not loaded")?;
    let Some(action) = glb.allacts.get_current() else {
        return Err(IfaceError::Execution("No action set".to_string()));
    };
    let mut text = String::new();
    action.print_statistics(&mut text);
    out_write(&fileoptr, &text);
    Ok(())
}

pub fn ifc_reset_actionstats(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let dcp = decomp_data(status);
    let glb = conf_mut(dcp, "Image not loaded")?;
    let Some(action) = glb.allacts.get_current() else {
        return Err(IfaceError::Execution("No action set".to_string()));
    };
    action.reset_stats();
    Ok(())
}

pub fn ifc_count_pcode(_args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let dcp = decomp_data(status);
    conf_mut(dcp, "Image not loaded")?;
    if dcp.fd.is_none() {
        return Err(no_function("No function selected"));
    }
    with_current_function(dcp, |fd, _glb| {
        let mut count: u32 = 0;
        let mut iter = fd.begin_op_alive();
        let enditer = fd.end_op_alive();
        while iter != enditer {
            count += 1;
            iter = iter.and_then(|op| fd.obank.next_in_list(op, crate::op::PcodeOp::INSERT_LIST));
        }
        out_write(&optr, &format!("Count - pcode = {count}\n"));
        Ok(())
    })
}

fn extrapop_text(expop: i32) -> String {
    if expop == ProtoModel::EXTRAPOP_UNKNOWN {
        "unknown".to_string()
    } else {
        expop.to_string()
    }
}

pub fn ifc_print_extrapop(args: &mut IStream, status: &mut IfaceStatus) -> IfaceResult<()> {
    let optr = status.optr.clone();
    let mut name = String::new();
    args.ws().read_word_into(&mut name);
    let dcp = decomp_data(status);
    let fdsym = dcp.fd;
    let glb = conf_mut(dcp, "No load image present")?;
    if name.is_empty() {
        match fdsym {
            Some(sym) => with_function(glb, sym, |fd, _glb| {
                let mut text = String::new();
                for index in 0..fd.num_calls() {
                    let fc = fd.call_spec(fd.get_call_specs(index));
                    text.push_str(&format!("ExtraPop for {}(", fc.get_name()));
                    let opaddr = fd.op(fc.get_op()).get_addr().clone();
                    text.push_str(&address_text(&opaddr));
                    text.push(')');
                    text.push(' ');
                    text.push_str(&extrapop_text(fc.get_effective_extra_pop()));
                    text.push('(');
                    text.push_str(&extrapop_text(fc.get_extra_pop()));
                    text.push_str(")\n");
                }
                out_write(&optr, &text);
                Ok(())
            })?,
            None => {
                let model = glb
                    .defaultfp
                    .ok_or_else(|| IfaceError::Core(Error::Lowlevel("missing default prototype".to_string())))?;
                let expop = glb.proto_models.get(model).get_extra_pop();
                out_write(&optr, &format!("Default extra pop = {}\n", extrapop_text(expop)));
            }
        }
        return Ok(());
    }
    let scope = super::global_scope(glb)?;
    let Some(target) = symbol_table(glb)?.scope_query_function_by_name(scope, &name) else {
        return Err(IfaceError::Execution(format!("Unknown function: {name}")));
    };
    let (expop, target_name) = with_function(glb, target, |fd, _glb| {
        Ok((fd.get_func_proto().get_extra_pop(), fd.get_name().to_string()))
    })?;
    out_write(
        &optr,
        &format!("ExtraPop for function {name} is {}\n", extrapop_text(expop)),
    );
    if let Some(sym) = fdsym {
        with_function(glb, sym, |fd, _glb| {
            let mut text = String::new();
            for index in 0..fd.num_calls() {
                let fc = fd.call_spec(fd.get_call_specs(index));
                if fc.get_name() == target_name {
                    text.push_str("For this function, extrapop = ");
                    text.push_str(&extrapop_text(fc.get_effective_extra_pop()));
                    text.push('(');
                    text.push_str(&extrapop_text(fc.get_extra_pop()));
                    text.push_str(")\n");
                }
            }
            out_write(&optr, &text);
            Ok(())
        })?;
    }
    Ok(())
}

fn address_text(addr: &Address) -> String {
    let mut text = String::new();
    addr.print_raw(&mut text);
    text
}

pub fn current_function_name(status: &mut IfaceStatus) -> IfaceResult<String> {
    let dcp = decomp_data(status);
    let sym = dcp.fd.ok_or_else(|| no_function("No function selected"))?;
    let glb = conf_mut(dcp, "No function selected")?;
    function_name(glb, sym)
}
