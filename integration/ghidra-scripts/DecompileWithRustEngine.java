// Live Ghidra database bridge for ghidra-rust-worker.
// Run from Script Manager with the cursor inside the function to decompile.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class DecompileWithRustEngine extends GhidraScript {
    private static final int MAX_FRAME_BYTES = 15 * 1024 * 1024;
    private static final long MAX_MEMORY_BYTES = 6L * 1024 * 1024;
    private static final int MAX_BLOCK_BYTES = 6 * 1024 * 1024;

    private static String json(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i=0;i<value.length();i++) {
            char c=value.charAt(i);
            if(c=='"') out.append("\\\"");
            else if(c=='\\') out.append("\\\\");
            else if(c=='\n') out.append("\\n");
            else if(c=='\r') out.append("\\r");
            else if(c=='\t') out.append("\\t");
            else if(c<32) out.append(String.format("\\u%04x",(int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    private static String hex(byte[] bytes) {
        char[] out=new char[bytes.length*2];
        char[] digits="0123456789abcdef".toCharArray();
        for(int i=0;i<bytes.length;i++){int v=bytes[i]&255;out[i*2]=digits[v>>>4];out[i*2+1]=digits[v&15];}
        return new String(out);
    }
    private static String addr(Address address) {
        return Long.toUnsignedString(address.getOffset());
    }
    private String snapshot(String id) throws Exception {
        StringBuilder blocks=new StringBuilder("[");
        StringBuilder functions=new StringBuilder("[");
        StringBuilder symbols=new StringBuilder("[");
        StringBuilder comments=new StringBuilder("[");
        StringBuilder references=new StringBuilder("[");
        int nb=0,nf=0,ns=0,nc=0,nr=0;
        long memoryBytes=0;

        for(MemoryBlock block:currentProgram.getMemory().getBlocks()) {
            if(!block.isInitialized() || block.getSize()<=0) continue;
            long size=block.getSize();
            if(size>MAX_BLOCK_BYTES || memoryBytes+size>MAX_MEMORY_BYTES) {
                println("Snapshot limit: omitted memory block "+block.getName()+" ("+size+" bytes).");
                continue;
            }
            byte[] data=new byte[(int)size];
            currentProgram.getMemory().getBytes(block.getStart(),data);
            if(nb++>0) blocks.append(',');
            blocks.append("{\"start\":").append(json(addr(block.getStart())))
                .append(",\"bytes_hex\":").append(json(hex(data)))
                .append(",\"readable\":").append(block.isRead())
                .append(",\"writable\":").append(block.isWrite())
                .append(",\"executable\":").append(block.isExecute()).append('}');
            memoryBytes+=size;
        }

        FunctionIterator fi=currentProgram.getFunctionManager().getFunctions(true);
        while(fi.hasNext() && nf<30000) {
            Function f=fi.next();
            if(nf++>0) functions.append(',');
            functions.append("{\"entry\":").append(json(addr(f.getEntryPoint())))
                .append(",\"name\":").append(json(f.getName()))
                .append(",\"body_size\":").append(f.getBody().getNumAddresses())
                .append(",\"calling_convention\":").append(json(f.getCallingConventionName()))
                .append(",\"return_type\":").append(json(f.getReturnType().getDisplayName()))
                .append(",\"namespace\":").append(json(f.getParentNamespace().getName(true)))
                .append(",\"parameters\":[");
            Parameter[] parameters=f.getParameters();
            for(int i=0;i<parameters.length;i++) {
                if(i>0) functions.append(',');
                Parameter parameter=parameters[i];
                functions.append("{\"ordinal\":").append(i)
                    .append(",\"name\":").append(json(parameter.getName()))
                    .append(",\"type_name\":").append(json(parameter.getDataType().getDisplayName()))
                    .append(",\"storage\":").append(json(parameter.getVariableStorage().toString())).append('}');
            }
            functions.append("]}");
        }

        SymbolIterator si=currentProgram.getSymbolTable().getAllSymbols(true);
        while(si.hasNext() && ns<50000) {
            Symbol s=si.next();
            if(ns++>0) symbols.append(',');
            symbols.append("{\"address\":").append(json(addr(s.getAddress())))
                .append(",\"name\":").append(json(s.getName()))
                .append(",\"kind\":").append(json(s.getSymbolType().toString().toLowerCase(Locale.ROOT)))
                .append(",\"size\":1,\"namespace\":").append(json(s.getParentNamespace().getName(true))).append('}');
        }

        CodeUnitIterator units=currentProgram.getListing().getCodeUnits(true);
        int[] commentTypes={CodeUnit.PLATE_COMMENT,CodeUnit.PRE_COMMENT,CodeUnit.EOL_COMMENT,CodeUnit.REPEATABLE_COMMENT,CodeUnit.POST_COMMENT};
        String[] commentNames={"plate","pre","eol","repeatable","post"};
        while(units.hasNext() && (nc<50000 || nr<100000)) {
            CodeUnit unit=units.next();
            Address at=unit.getMinAddress();
            for(int i=0;i<commentTypes.length && nc<50000;i++) {
                String value=unit.getComment(commentTypes[i]);
                if(value==null || value.isEmpty()) continue;
                if(nc++>0) comments.append(',');
                Function owner=currentProgram.getFunctionManager().getFunctionContaining(at);
                comments.append("{\"address\":").append(json(addr(at))).append(",\"function_entry\":")
                    .append(owner==null?"null":json(addr(owner.getEntryPoint())))
                    .append(",\"kind\":").append(json(commentNames[i])).append(",\"text\":").append(json(value)).append('}');
            }
            if(nr<100000) {
                Reference[] outgoing=currentProgram.getReferenceManager().getReferencesFrom(at);
                for(Reference ref:outgoing) {
                    if(nr>=100000) break;
                    if(nr++>0) references.append(',');
                    references.append("{\"from\":").append(json(addr(ref.getFromAddress())))
                        .append(",\"to\":").append(json(addr(ref.getToAddress())))
                        .append(",\"kind\":").append(json(ref.getReferenceType().toString()))
                        .append(",\"is_primary\":").append(ref.isPrimary()).append('}');
                }
            }
        }
        blocks.append(']'); functions.append(']'); symbols.append(']');
        comments.append(']'); references.append(']');
        String payload="{\"name\":"+json(currentProgram.getName())
            +",\"language_id\":"+json(currentProgram.getLanguageID().toString())
            +",\"compiler_spec_id\":"+json(currentProgram.getCompilerSpec().getCompilerSpecID().toString())
            +",\"endianness\":"+json(currentProgram.getLanguage().isBigEndian()?"big":"little")
            +",\"memory_blocks\":"+blocks+",\"functions\":"+functions+",\"symbols\":"+symbols
            +",\"comments\":"+comments+",\"references\":"+references+"}";
        return "{\"protocol_version\":1,\"request_id\":"+json(id)+",\"command\":\"open_program\",\"payload\":"+payload+"}\n";
    }

    @Override protected void run() throws Exception {
        if(currentProgram==null || currentAddress==null) { printerr("Open a program and place the cursor inside a function."); return; }
        Function target=currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
        if(target==null) { printerr("The current address is not inside a function."); return; }
        String configured=System.getProperty("ghidra.rust.engine");
        if(configured==null || configured.isBlank()) configured=System.getenv("GHIDRA_RUST_ENGINE");
        File worker=configured==null || configured.isBlank()
            ? askFile("Select ghidra-rust-worker executable","Select") : new File(configured);
        if(worker==null || !worker.isFile() || !worker.canExecute()) { printerr("Select an executable ghidra-rust-worker binary."); return; }

        Process process=new ProcessBuilder(worker.getAbsolutePath()).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        try {
            BufferedWriter input=new BufferedWriter(new OutputStreamWriter(process.getOutputStream(),StandardCharsets.UTF_8));
            BufferedReader output=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8));
            String open=snapshot("open-1");
            if(open.getBytes(StandardCharsets.UTF_8).length>MAX_FRAME_BYTES) {
                printerr("The exported database metadata exceeds the JSON frame limit."); process.destroyForcibly(); return;
            }
            input.write(open); input.newLine(); input.flush();
            String opened=output.readLine();
            if(opened==null) { printerr("Rust worker closed before acknowledging the Ghidra database."); return; }
            println("Ghidra database hydration: "+opened);

            String decompile="{\"protocol_version\":1,\"request_id\":\"decompile-1\",\"command\":\"decompile\",\"payload\":{\"function_address\":"+json(addr(target.getEntryPoint()))+"}}";
            input.write(decompile); input.newLine(); input.flush();
            String result=output.readLine();
            if(result==null) printerr("Rust worker closed without returning a decompilation result.");
            else println("Rust decompiler response: "+result);
            input.write("{\"protocol_version\":1,\"request_id\":\"shutdown\",\"command\":\"shutdown\"}");
            input.newLine(); input.flush(); input.close();

            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(300);
            while(!process.waitFor(150,TimeUnit.MILLISECONDS)) {
                if(monitor.isCancelled()) { process.destroyForcibly(); throw new CancelledException(); }
                if(System.nanoTime()>deadline) { process.destroyForcibly(); printerr("Rust worker timed out."); return; }
                monitor.setMessage("Rust decompiler: analyzing "+target.getName());
            }
        } finally { if(process.isAlive()) process.destroyForcibly(); }
    }
}
