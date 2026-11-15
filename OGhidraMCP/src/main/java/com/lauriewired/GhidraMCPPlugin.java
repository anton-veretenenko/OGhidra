/*
 * OGhidraMCP - Extended GhidraMCP Plugin
 *
 * Original Author: LaurieWired (https://github.com/LaurieWired/GhidraMCP)
 * Multi-Instance Architecture inspired by GhydraMCP (https://github.com/starsong/GhydraMCP)
 * Modified by: ezrealenoch
 *
 * This is a modified version of GhidraMCP with additional capabilities:
 *   - read_bytes: Read raw bytes from memory addresses for AI analysis
 *   - Multi-instance support (dynamic port allocation)
 *
 * Original project: https://github.com/LaurieWired/GhidraMCP
 * License: See original project for license terms
 */
package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.SignedQWordDataType;
import ghidra.program.model.data.SignedWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.WideCharDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.util.CodeUnitInsertionException;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "OGhidraMCP - Extended HTTP server plugin", description = "Extended GhidraMCP by LaurieWired, modified by ezrealenoch. "
        +
        "Starts an embedded HTTP server to expose program data for AI-assisted analysis. " +
        "Includes raw byte reading capability. Port configurable via Tool Options.")
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    // Multi-instance support
    public static final Map<Integer, GhidraMCPPlugin> activeInstances = new ConcurrentHashMap<>();
    private int currentPort;
    private static final int MAX_PORT_ATTEMPTS = 10;
    private static final int DYNAMIC_PORT_START = 8192;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
                null, // No help location for now
                "The network port number the embedded HTTP server will listen on. " +
                        "If set to 8080, plugin will automatically try 8192+ if 8080 is taken (Multi-instance mode).");

        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int configuredPort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
            if (activeInstances.containsKey(currentPort)) {
                activeInstances.remove(currentPort);
            }
        }

        // Find available port (Dynamic separation logic)
        this.currentPort = findAvailablePort(configuredPort);

        // Register this instance
        activeInstances.put(this.currentPort, this);

        server = HttpServer.create(new InetSocketAddress(this.currentPort), 0);

        // --- NEW DISCOVERY ENDPOINTS (For GhydraMCP Compatibility) ---

        // Plugin version endpoint (used for discovery)
        server.createContext("/plugin-version", exchange -> {
            String json = "{\"result\": {\"plugin_version\": \"Custom-OGhidraMCP\", \"api_version\": \"1.0\"}}";
            sendJsonResponse(exchange, json);
        });

        // Program info endpoint (used for instance info)
        server.createContext("/program", exchange -> {
            Program prog = getCurrentProgram();
            if (prog != null) {
                String name = prog.getName();
                String pid = prog.getDomainFile().getProjectLocator().getName() + ":" + name;
                String json = String.format("{\"result\": {\"name\": \"%s\", \"programId\": \"%s\"}}", name, pid);
                sendJsonResponse(exchange, json);
            } else {
                sendJsonResponse(exchange, "{\"result\": {}}");
            }
        });

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name, offset, limit));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully"
                    : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.containsKey("address")
                    ? params.get("address")
                    : params.get("new_address");
            String newName = params.containsKey("newName")
                    ? params.get("newName")
                    : params.get("new_name");
            sendResponse(exchange, renameDataAtAddress(address, newName));
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listFunctions(offset, limit));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, decompileFunctionByAddress(address, offset, limit));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                    .append(" to ").append(newType)
                    .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // Raw byte reading endpoint for AI analysis
        server.createContext("/read_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            String format = qparams.getOrDefault("format", "hex");
            sendResponse(exchange, readBytesFromAddress(address, length, format));
        });

        // Create a function over an address that auto-analysis left undefined.
        // Optional name; disassemble_first defaults to true (same as REA seeds).
        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            boolean disassembleFirst = !"false".equalsIgnoreCase(
                    params.getOrDefault("disassemble_first", "true"));
            boolean success = createFunctionAt(address, name, disassembleFirst);
            sendResponse(exchange, success
                    ? "Function created successfully"
                    : "Failed to create function");
        });

        // Persist the analysis database (names, comments, types).  Without
        // this, edits live only in memory until the analyst saves the project.
        server.createContext("/save_program", exchange -> {
            boolean success = saveCurrentProgram();
            sendResponse(exchange, success
                    ? "Program saved successfully"
                    : "Failed to save program");
        });

        // --- Disassembly, data markup and structure endpoints -------------
        // See emulator/docs/ghidra-mcp-plan.md.  Write endpoints are one
        // transaction each; the destructive ones require confirm/reason/
        // evidence (destructiveGuard).

        server.createContext("/disassemble", exchange -> {
            sendResponse(exchange, disassembleAt(parsePostParams(exchange)));
        });

        server.createContext("/undefine", exchange -> {
            sendResponse(exchange, undefineRange(parsePostParams(exchange)));
        });

        server.createContext("/create_data", exchange -> {
            sendResponse(exchange, createDataAt(parsePostParams(exchange)));
        });

        // Alias for re-typing an existing code unit: /undefine + /create_data.
        server.createContext("/set_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            if (!params.containsKey("type")) {
                String type = params.containsKey("new_type")
                        ? params.get("new_type")
                        : params.get("data_type");
                params.put("type", type);
            }
            params.putIfAbsent("overwrite", "true");
            sendResponse(exchange, createDataAt(params));
        });

        server.createContext("/delete_function", exchange -> {
            sendResponse(exchange, deleteFunctionAt(parsePostParams(exchange)));
        });

        server.createContext("/create_label", exchange -> {
            sendResponse(exchange, createLabelAt(parsePostParams(exchange)));
        });

        server.createContext("/variables", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listFunctionVariables(q.get("function_address"),
                    parseIntOrDefault(q.get("offset"), 0),
                    parseIntOrDefault(q.get("limit"), 100)));
        });

        server.createContext("/data_types", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listDataTypes(q.get("query"),
                    parseIntOrDefault(q.get("offset"), 0),
                    parseIntOrDefault(q.get("limit"), 100)));
        });

        server.createContext("/set_comment", exchange -> {
            sendResponse(exchange, setCommentByType(parsePostParams(exchange)));
        });

        server.createContext("/basic_blocks", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listBasicBlocks(q.get("address"),
                    parseIntOrDefault(q.get("offset"), 0),
                    parseIntOrDefault(q.get("limit"), 100)));
        });

        server.createContext("/call_graph", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, callGraph(q.get("address"),
                    parseIntOrDefault(q.get("depth"), 2),
                    q.get("direction")));
        });

        server.createContext("/search_bytes", exchange -> {
            sendResponse(exchange, searchBytes(parsePostParams(exchange)));
        });

        server.createContext("/bookmark", exchange -> {
            sendResponse(exchange, addBookmark(parsePostParams(exchange)));
        });

        server.createContext("/bookmarks", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listBookmarks(q.get("type"),
                    parseIntOrDefault(q.get("offset"), 0),
                    parseIntOrDefault(q.get("limit"), 100)));
        });

        server.createContext("/undo", exchange -> {
            sendResponse(exchange, undoRedo(true,
                    parseIntOrDefault(parsePostParams(exchange).get("steps"), 1)));
        });

        server.createContext("/redo", exchange -> {
            sendResponse(exchange, undoRedo(false,
                    parseIntOrDefault(parsePostParams(exchange).get("steps"), 1)));
        });

        server.createContext("/undo_state", exchange -> {
            sendResponse(exchange, undoState());
        });

        server.createContext("/batch", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8);
            sendResponse(exchange, runBatch(body));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + this.currentPort);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + this.currentPort + ". Port might be in use.",
                        e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    /**
     * Find an available port based on configuration.
     *
     * Multi-instance port allocation logic adapted from GhydraMCP project:
     * https://github.com/starsong/GhydraMCP
     * Authors: starsong and contributors
     *
     * This implementation allows multiple Ghidra instances to run simultaneously,
     * each on a unique port. It prioritizes the lowest available port in a
     * queue-like fashion.
     */
    private int findAvailablePort(int basePort) {
        // If user specifically requested something other than default 8080, respect it
        // strictly first
        if (basePort != DEFAULT_PORT) {
            if (isPortAvailable(basePort))
                return basePort;
            Msg.warn(this, "Configured port " + basePort + " is in use. Falling back to default/dynamic allocation.");
        }

        // Try standard default port 8080 explicitly
        if (isPortAvailable(DEFAULT_PORT)) {
            return DEFAULT_PORT;
        }

        // Then try dynamic range 8192+ (Skipping 8081-8089 as per requirement)
        for (int i = 0; i < MAX_PORT_ATTEMPTS; i++) {
            int candidate = DYNAMIC_PORT_START + i;
            if (isPortAvailable(candidate)) {
                return candidate;
            }
        }

        throw new RuntimeException("Could not find open port: 8080 or " + DYNAMIC_PORT_START + "+");
    }

    private boolean isPortAvailable(int port) {
        if (activeInstances.containsKey(port))
            return false;
        try (ServerSocket s = new ServerSocket(port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        // Get external symbols (imports)
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            StringBuilder line = new StringBuilder();
            line.append(symbol.getName()).append(" -> ").append(symbol.getAddress());

            // Get references to this import (xrefs)
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(symbol.getAddress());
            List<String> callers = new ArrayList<>();
            int refCount = 0;

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                refCount++;

                // If count is small, collect caller names
                if (refCount <= 5) {
                    Address fromAddr = ref.getFromAddress();
                    Function caller = program.getFunctionManager().getFunctionContaining(fromAddr);
                    if (caller != null) {
                        callers.add(caller.getName());
                    } else {
                        callers.add(fromAddr.toString());
                    }
                }
            }

            // Append reference info
            if (refCount > 0) {
                line.append(" [Refs: ").append(refCount).append("]");
                if (!callers.isEmpty()) {
                    line.append(" [Callers: ").append(String.join(", ", callers));
                    if (refCount > 5) {
                        line.append(", ...");
                    }
                    line.append("]");
                }
            }

            lines.add(line.toString());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                            data.getAddress(),
                            escapeNonAscii(label),
                            escapeNonAscii(valRepr)));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty())
            return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return paginateString(result.getDecompiledFunction().getC(), offset, limit);
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                } finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    /**
     * Rename the label at an address, or create one when the address has no
     * defined data yet.  The old version silently did nothing in the latter
     * case (it required {@code getDefinedDataAt != null}).
     */
    private String renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        Address addr = parseAddress(program, addressStr);
        if (addr == null)
            return "address= is required";
        if (newName == null || newName.trim().isEmpty())
            return "new_name= is required";

        AtomicReference<String> failure = new AtomicReference<>();
        boolean ok = inTransaction("Rename data via HTTP", prog -> {
            try {
                SymbolTable symTable = prog.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);
                if (symbol != null) {
                    symbol.setName(newName.trim(), SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(addr, newName.trim(), SourceType.USER_DEFINED);
                }
                return true;
            } catch (Exception e) {
                failure.set(e.toString());
                return false;
            }
        });
        return ok
                ? "Renamed label at " + addr + " to '" + newName.trim() + "'"
                : "Failed to rename label at " + addr
                        + (failure.get() != null ? ": " + failure.get() : "");
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                                ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                            finalHighSymbol,
                            newVarName,
                            null,
                            SourceType.USER_DEFINED);
                    successFlag.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                } finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's
     * idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     *
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction  is the given HighFunction
     * @return true if there is a difference (and a full commit is required)
     */
    protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can
            // match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null)
                return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                    func.getName(),
                    func.getEntryPoint(),
                    func.getSignature(),
                    func.getEntryPoint(),
                    func.getBody().getMinAddress(),
                    func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null)
            return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null)
            return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null)
            return "No current location";

        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null)
            return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        List<String> functions = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            functions.add(String.format("%s at %s",
                    func.getName(),
                    func.getEntryPoint()));
        }

        return paginateList(functions, offset, limit);
    }

    /**
     * Gets a function at the given address or containing the address
     *
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null)
                return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            String code = (result != null && result.decompileCompleted())
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed";

            return paginateString(code, offset, limit);
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null)
                return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n",
                        instr.getAddress(),
                        instr.toString(),
                        comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null)
            return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null)
            return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
                newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Create a function at an address that is not part of any function yet.
     *
     * This is the on-demand counterpart of Ghidra's "Create Function"
     * action and of REA's pre-analysis function seeds: the entry address is
     * disassembled first (unless disassemble_first=false), then
     * CreateFunctionCmd computes the body.  An optional name is applied
     * afterwards with USER_DEFINED source, exactly like the rename path.
     */
    private boolean createFunctionAt(String addressStr, String name, boolean disassembleFirst) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null || addressStr.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function via HTTP");
                try {
                    Address addr = program.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(addressStr);
                    if (program.getFunctionManager().getFunctionAt(addr) != null) {
                        Msg.warn(this, "Function already exists at " + addressStr);
                        return;
                    }

                    if (disassembleFirst
                            && program.getListing().getInstructionAt(addr) == null) {
                        AddressSet range = new AddressSet(addr, addr);
                        DisassembleCommand dis =
                                new DisassembleCommand(range, null, true);
                        if (!dis.applyTo(program, new ConsoleTaskMonitor())) {
                            Msg.error(this, "Failed to disassemble at " + addressStr
                                    + ": " + dis.getStatusMsg());
                            return;
                        }
                    }

                    CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
                    if (!cmd.applyTo(program, new ConsoleTaskMonitor())) {
                        Msg.error(this, "Failed to create function at " + addressStr
                                + ": " + cmd.getStatusMsg());
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        Msg.error(this, "Function creation reported success but no "
                                + "function exists at " + addressStr);
                        return;
                    }
                    if (name != null && !name.isEmpty()) {
                        func.setName(name, SourceType.USER_DEFINED);
                    }
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating function at " + addressStr, e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute create function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Save the current program (analysis database) to its project.
     *
     * CreateFunctionCmd schedules a background Auto Analysis task; calling
     * save in the same instant fails with "Unable to lock due to active
     * transaction".  Retry briefly on the HTTP thread (never sleeping on the
     * Swing EDT) so create_function followed by save_program works.
     */
    private boolean saveCurrentProgram() {
        Program program = getCurrentProgram();
        if (program == null) {
            return false;
        }

        for (int attempt = 0; attempt < 30; attempt++) {
            AtomicBoolean saved = new AtomicBoolean(false);
            AtomicReference<Exception> failure = new AtomicReference<>();
            try {
                SwingUtilities.invokeAndWait(() -> {
                    try {
                        program.save("Saved by GhidraMCP HTTP request",
                                new ConsoleTaskMonitor());
                        saved.set(true);
                    } catch (Exception e) {
                        failure.set(e);
                    }
                });
            } catch (InterruptedException | InvocationTargetException e) {
                Msg.error(this, "Failed to execute save program on Swing thread", e);
                return false;
            }

            if (saved.get()) {
                return true;
            }
            String message = String.valueOf(failure.get());
            if (!message.contains("active transaction")) {
                Msg.error(this, "Failed to save program", failure.get());
                return false;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        Msg.error(this, "Failed to save program: program stayed busy after retries");
        return false;
    }

    /**
     * Set a function's prototype with proper error handling using
     * ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null)
            return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(
                    () -> applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
            AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                    func.getEntryPoint(),
                    CodeUnit.PLATE_COMMENT,
                    "Setting prototype: " + prototype);
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
            AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = tool
                    .getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = new ghidra.app.util.parser.FunctionSignatureParser(
                    dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null)
            return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
                variableName == null || variableName.isEmpty() ||
                newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities
                    .invokeAndWait(() -> applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr,
            String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName +
                    " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                    symbol, // The high symbol to modify
                    symbol.getName(), // Keep original name
                    dataType, // The new data type
                    SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "Error: Invalid address format or address not found: " + addressStr;
            }
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "Error: Invalid address format or address not found: " + addressStr;
            }
            ReferenceManager refManager = program.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name.
     * Now also supports external/imported symbols (e.g., LoadLibraryW,
     * CreateFileW).
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (functionName == null || functionName.isEmpty())
            return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            ReferenceManager refManager = program.getReferenceManager();
            SymbolTable symbolTable = program.getSymbolTable();

            Address targetAddress = null;
            String targetType = "function";

            // First, try to find as a regular function in FunctionManager
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    targetAddress = function.getEntryPoint();
                    break;
                }
            }

            // If not found in functions, check external symbols (imports)
            if (targetAddress == null) {
                for (Symbol symbol : symbolTable.getExternalSymbols()) {
                    if (symbol.getName().equals(functionName)) {
                        targetAddress = symbol.getAddress();
                        targetType = "external";
                        break;
                    }
                }
            }

            // Still not found? Try all symbols matching the name
            if (targetAddress == null) {
                SymbolIterator symIt = symbolTable.getSymbols(functionName);
                if (symIt.hasNext()) {
                    Symbol symbol = symIt.next();
                    targetAddress = symbol.getAddress();
                    targetType = symbol.getSymbolType().toString().toLowerCase();
                }
            }

            if (targetAddress == null) {
                return "Function or symbol not found: " + functionName;
            }

            // Get all references to this address
            ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            if (refs.isEmpty()) {
                return "No references found to " + targetType + ": " + functionName + " (at " + targetAddress + ")";
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    /**
     * List all defined strings in the program with their addresses
     */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null)
            return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null)
            return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int) c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     *
     * @param dtm      The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive)
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Raw byte reading methods
    // ----------------------------------------------------------------------------------

    /**
     * Read raw bytes from memory at specified address
     *
     * @param addressStr The starting address in hex format
     * @param length     Number of bytes to read (1-4096)
     * @param format     Output format: "hex" for hex dump, "raw" for base64 encoded
     * @return Formatted byte data or error message
     */
    private String readBytesFromAddress(String addressStr, int length, String format) {
        Program program = getCurrentProgram();
        if (program == null)
            return "No program loaded";
        if (addressStr == null || addressStr.isEmpty())
            return "Address is required";
        if (length <= 0 || length > 4096)
            return "Length must be 1-4096 bytes";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null)
                return "Invalid address: " + addressStr;

            byte[] bytes = new byte[length];
            int bytesRead = program.getMemory().getBytes(addr, bytes);

            if (bytesRead <= 0)
                return "Could not read bytes at address: " + addressStr;

            if ("raw".equals(format)) {
                // Return base64 encoded bytes for programmatic processing
                return java.util.Base64.getEncoder().encodeToString(
                        java.util.Arrays.copyOf(bytes, bytesRead));
            }
            // Default: return formatted hex dump
            return formatHexDump(addr, bytes, bytesRead);
        } catch (ghidra.program.model.mem.MemoryAccessException e) {
            return "Memory access error at " + addressStr + ": " + e.getMessage();
        } catch (Exception e) {
            return "Error reading bytes: " + e.getMessage();
        }
    }

    /**
     * Format bytes as a traditional hex dump with address, hex bytes, and ASCII
     * representation
     *
     * @param startAddr Starting address for the dump
     * @param bytes     The byte array to format
     * @param length    Number of valid bytes in the array
     * @return Formatted hex dump string
     */
    private String formatHexDump(Address startAddr, byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int i = 0; i < length; i += bytesPerLine) {
            // Address column
            sb.append(String.format("%s: ", startAddr.add(i)));

            // Hex bytes column
            for (int j = 0; j < bytesPerLine && (i + j) < length; j++) {
                sb.append(String.format("%02X ", bytes[i + j] & 0xFF));
            }

            // Padding for incomplete lines
            for (int j = length - i; j < bytesPerLine && i + bytesPerLine > length; j++) {
                sb.append("   ");
            }

            // ASCII representation column
            sb.append(" |");
            for (int j = 0; j < bytesPerLine && (i + j) < length; j++) {
                byte b = bytes[i + j];
                sb.append((b >= 32 && b < 127) ? (char) b : '.');
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     * Handles edge cases: empty values (key=), values with = in them, missing
     * values
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                // Use split with limit=2 to handle values containing '='
                String[] kv = p.split("=", 2);
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = "";
                    if (kv.length == 2) {
                        value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    }
                    // Only add if we have a key
                    if (!key.isEmpty()) {
                        result.put(key, value);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter: " + p, e);
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            // limit=2 keeps '=' inside values (comments, prototypes, JSON-ish args)
            String[] kv = pair.split("=", 2);
            if (kv.length >= 1 && !kv[0].isEmpty()) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = kv.length == 2
                            ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8)
                            : "";
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying
     * offset & limit.
     * Includes metadata header with total count and pagination info.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int total = items.size();
        int start = Math.max(0, offset);
        int end = Math.min(total, offset + limit);

        if (start >= total) {
            return String.format("[Total: %d] [Showing: 0 items - offset %d exceeds total]", total, offset);
        }

        List<String> sub = items.subList(start, end);
        String content = String.join("\n", sub);

        // Build metadata header
        StringBuilder header = new StringBuilder();
        header.append(String.format("[Total: %d] [Showing: %d-%d]", total, start + 1, end));

        // Add next page hint if more items exist
        if (end < total) {
            header.append(String.format(" [Next: offset=%d, limit=%d]", end, limit));
        }

        return header.toString() + "\n" + content;
    }

    /**
     * Paginate a large string by splitting it into lines
     */
    private String paginateString(String content, int offset, int limit) {
        if (content == null)
            return "";
        content = content.trim(); // Trim leading/trailing whitespace
        String[] lines = content.split("\\r?\\n");
        int total = lines.length;
        int start = Math.max(0, offset);
        int end = Math.min(total, offset + limit);

        if (start >= total) {
            return String.format("[Total Lines: %d] [Showing: 0 lines - offset %d exceeds total]", total, offset);
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[Total Lines: %d] [Showing Lines: %d-%d]\n", total, start + 1, end));

        for (int i = start; i < end; i++) {
            sb.append(lines[i]).append("\n");
        }

        if (end < total) {
            sb.append(String.format("... [Next: offset=%d, limit=%d]", end, limit));
        }

        return sb.toString();
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null)
            return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null)
            return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Phase 2: disassembly, data markup, structure, undo and batch
    // See emulator/docs/ghidra-mcp-plan.md.
    // ------------------------------------------------------------------

    private interface TxBody {
        boolean run(Program program) throws Exception;
    }

    private static final int DANGER_MIN_REASON = 12;
    private static final int DANGER_MIN_EVIDENCE = 24;

    private static String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static String firstNonEmpty(Map<String, String> params, String... keys) {
        for (String key : keys) {
            String value = params.get(key);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    private static List<String> last(List<String> values, int count) {
        if (values == null) {
            return Collections.emptyList();
        }
        int from = Math.max(0, values.size() - count);
        return values.subList(from, values.size());
    }

    private static String oneLine(String text) {
        String flat = trimToEmpty(text).replaceAll("\\s*\\R\\s*", " | ");
        return flat.length() > 300 ? flat.substring(0, 297) + "..." : flat;
    }

    /**
     * Run a body inside a Ghidra transaction on the Swing thread, so the
     * domain object is never touched from the HTTP thread.
     */
    private boolean inTransaction(String name, TxBody body) {
        Program program = getCurrentProgram();
        if (program == null) {
            return false;
        }
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(name);
                boolean ok = false;
                try {
                    ok = body.run(program);
                } catch (Exception e) {
                    Msg.error(this, "Error in " + name, e);
                } finally {
                    success.set(program.endTransaction(tx, ok) && ok);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + name + " on Swing thread", e);
        }
        return success.get();
    }

    private Address parseAddress(Program program, String text) {
        String trimmed = trimToEmpty(text);
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            return program.getAddressFactory().getAddress(trimmed);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Guard for endpoints that destroy markup: /undefine, /delete_function and
     * /create_data (or /set_data_type) with overwrite=true.  The caller must
     * supply confirm=true, a concrete reason and evidence taken from the
     * program (xrefs, decompilation, disassembly, documented addresses).
     */
    private String destructiveGuard(Map<String, String> params, String operation) {
        String reason = trimToEmpty(params.get("reason"));
        String evidence = trimToEmpty(params.get("evidence"));
        if (!"true".equalsIgnoreCase(trimToEmpty(params.get("confirm")))) {
            return "REFUSED: /" + operation + " is destructive. Re-run with confirm=true, "
                    + "reason=<what and why>, evidence=<xrefs/decompile/disassembly proving it>.";
        }
        if (reason.length() < DANGER_MIN_REASON) {
            return "REFUSED: reason= must be at least " + DANGER_MIN_REASON
                    + " characters and say what is being changed and why.";
        }
        if (evidence.length() < DANGER_MIN_EVIDENCE) {
            return "REFUSED: evidence= must be at least " + DANGER_MIN_EVIDENCE
                    + " characters and cite concrete proof (xrefs_to, /decompile_function, "
                    + "/disassemble or a documented address).";
        }
        Msg.warn(this, "DESTRUCTIVE /" + operation + " reason=[" + reason + "] evidence=[" + evidence + "]");
        return null;
    }

    private String disassembleAt(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required (e.g. address=0x0080cc6e)";
        }
        int length = Math.max(1, Math.min(parseIntOrDefault(params.get("length"), 4), 256));
        boolean followFlow = !"false".equalsIgnoreCase(trimToEmpty(params.get("follow_flow")));
        boolean overwrite = "true".equalsIgnoreCase(trimToEmpty(params.get("overwrite")));
        Address end = addr.add(length - 1);

        Instruction existing = program.getListing().getInstructionAt(addr);
        if (existing != null && !overwrite) {
            return "Already disassembled at " + addr + ": " + existing
                    + " (pass overwrite=true to redo)";
        }

        AtomicReference<String> status = new AtomicReference<>("");
        boolean ok = inTransaction("Disassemble via HTTP", prog -> {
            Listing listing = prog.getListing();
            if (listing.getInstructionAt(addr) != null) {
                listing.clearCodeUnits(addr, end, false);
            }
            DisassembleCommand cmd = new DisassembleCommand(new AddressSet(addr, end), null, followFlow);
            boolean applied = cmd.applyTo(prog, new ConsoleTaskMonitor());
            status.set(trimToEmpty(cmd.getStatusMsg()));
            return applied;
        });

        StringBuilder sb = new StringBuilder();
        sb.append(ok ? "Disassembled" : "Failed to disassemble")
                .append(" at ").append(addr)
                .append(" (").append(length).append(" byte(s), follow_flow=").append(followFlow).append(")");
        if (!status.get().isEmpty()) {
            sb.append(": ").append(status.get());
        }
        sb.append("\n");
        InstructionIterator instructions = program.getListing().getInstructions(addr, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getAddress().compareTo(end) > 0) {
                break;
            }
            sb.append(instr.getAddress()).append(": ").append(instr).append("\n");
        }
        return sb.toString().trim() + " (revert with /undo)";
    }

    private String undefineRange(Map<String, String> params) {
        String refusal = destructiveGuard(params, "undefine");
        if (refusal != null) {
            return refusal;
        }
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required";
        }
        int length = Math.max(1, Math.min(parseIntOrDefault(params.get("length"), 1), 4096));
        Address end = addr.add(length - 1);

        int units = countCodeUnits(program, addr, end);
        if (units == 0) {
            return "Nothing defined in [" + addr + ", " + end + "]";
        }
        String functions = functionsInRange(program, addr, end);
        boolean ok = inTransaction("Undefine via HTTP", prog -> {
            prog.getListing().clearCodeUnits(addr, end, false);
            return true;
        });
        if (!ok) {
            return "Failed to undefine [" + addr + ", " + end + "]";
        }
        return "Undefined " + units + " code unit(s) in [" + addr + ", " + end + "]. "
                + "Functions touched: " + functions + ". Revert with /undo (name: "
                + trimToEmpty(program.getUndoName()) + ").";
    }

    private int countCodeUnits(Program program, Address start, Address end) {
        int count = 0;
        CodeUnitIterator it = program.getListing().getCodeUnits(start, true);
        while (it.hasNext()) {
            CodeUnit unit = it.next();
            if (unit.getAddress().compareTo(end) > 0) {
                break;
            }
            count++;
        }
        return count;
    }

    private String functionsInRange(Program program, Address start, Address end) {
        List<String> names = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(start, true);
        while (it.hasNext()) {
            Function func = it.next();
            if (func.getEntryPoint().compareTo(end) > 0) {
                break;
            }
            names.add(func.getName() + "@" + func.getEntryPoint());
        }
        return names.isEmpty() ? "none" : String.join(", ", names);
    }

    private DataType resolveDataType(Program program, String raw) {
        String name = trimToEmpty(raw);
        if (name.isEmpty()) {
            return null;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        switch (lower) {
            case "byte":
            case "u8":
            case "uint8":
                return new ByteDataType();
            case "sbyte":
            case "i8":
            case "int8":
                return new SignedByteDataType();
            case "word":
            case "u16":
            case "uint16":
                return new WordDataType();
            case "sword":
            case "i16":
            case "int16":
                return new SignedWordDataType();
            case "dword":
            case "u32":
            case "uint32":
                return new DWordDataType();
            case "sdword":
            case "i32":
            case "int32":
                return new SignedDWordDataType();
            case "qword":
            case "u64":
            case "uint64":
                return new QWordDataType();
            case "sqword":
            case "i64":
            case "int64":
                return new SignedQWordDataType();
            case "float":
            case "f32":
                return new FloatDataType();
            case "double":
            case "f64":
                return new DoubleDataType();
            case "pointer":
            case "ptr":
                return new PointerDataType(program.getDataTypeManager());
            case "char":
                return new CharDataType();
            case "wchar":
            case "widechar":
            case "wchar_t":
                return new WideCharDataType();
            case "string":
            case "cstring":
                return new TerminatedStringDataType();
            case "unicode":
            case "utf16":
                return new UnicodeDataType();
            case "undefined":
                return new Undefined1DataType();
            default:
                break;
        }
        if (lower.matches("undefined\\d+")) {
            try {
                int size = Integer.parseInt(lower.substring("undefined".length()));
                if (size > 0 && size <= 64) {
                    return Undefined.getUndefinedDataType(size);
                }
            } catch (NumberFormatException ignored) {
                // fall through to the data type manager lookup
            }
        }
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = dtm.getDataType(name);
        if (dt == null) {
            dt = dtm.getDataType("/" + name);
        }
        if (dt == null) {
            dt = findDataTypeByNameInAllCategories(dtm, name);
        }
        return dt;
    }

    private String createDataAt(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required";
        }
        String typeName = trimToEmpty(params.get("type"));
        if (typeName.isEmpty()) {
            return "type= is required (byte, word, dword, qword, pointer, undefined4, <struct name>)";
        }
        int count = parseIntOrDefault(params.get("count"),
                parseIntOrDefault(params.get("length"), 1));
        count = Math.max(1, Math.min(count, 4096));
        boolean overwrite = "true".equalsIgnoreCase(trimToEmpty(params.get("overwrite")));

        DataType base = resolveDataType(program, typeName);
        if (base == null) {
            return "Unknown data type '" + typeName + "'. Try byte/word/dword/qword/sbyte/sword/"
                    + "sdword/sqword/float/double/pointer/char/wchar/string/unicode/undefinedN "
                    + "or a name from /data_types.";
        }
        DataType effective = base;
        if (count > 1) {
            if (base.getLength() <= 0) {
                return "Cannot create an array of '" + typeName + "' (unknown element size)";
            }
            effective = new ArrayDataType(base, count, -1);
        }
        final DataType dataTypeToCreate = effective;

        CodeUnit existing = program.getListing().getCodeUnitAt(addr);
        if (existing != null && !overwrite) {
            return "REFUSED: " + existing.getClass().getSimpleName() + " already defined at " + addr
                    + " (" + existing + "). Pass overwrite=true with confirm/reason/evidence "
                    + "to replace it.";
        }
        if (existing != null) {
            String refusal = destructiveGuard(params, "create_data (overwrite=true)");
            if (refusal != null) {
                return refusal;
            }
        }

        int clearLength = Math.max(effective.getLength(),
                existing != null ? existing.getLength() : 1);
        Address clearEnd;
        try {
            clearEnd = addr.add(clearLength - 1);
        } catch (RuntimeException e) {
            return "Data does not fit at " + addr + ": " + e.getMessage();
        }

        AtomicInteger createdBytes = new AtomicInteger(0);
        AtomicReference<String> failure = new AtomicReference<>();
        boolean ok = inTransaction("Create data via HTTP", prog -> {
            try {
                prog.getListing().clearCodeUnits(addr, clearEnd, false);
                Data data = prog.getListing().createData(addr, dataTypeToCreate);
                if (data == null) {
                    failure.set("createData returned null");
                    return false;
                }
                createdBytes.set(data.getLength());
                return true;
            } catch (CodeUnitInsertionException e) {
                failure.set(e.getMessage());
                return false;
            }
        });
        if (!ok) {
            return "Failed to create " + typeName + " at " + addr
                    + (failure.get() != null ? ": " + failure.get() : "");
        }

        int bytes = Math.max(createdBytes.get(), effective.getLength());
        Address end;
        try {
            end = addr.add(bytes - 1);
        } catch (RuntimeException e) {
            end = addr;
        }
        return "Created " + typeName + (count > 1 ? "[" + count + "]" : "")
                + " (" + bytes + " bytes) at " + addr + " [" + addr + ", " + end
                + "]. Remove with /undefine (dangerous) or revert with /undo.";
    }

    private String deleteFunctionAt(Map<String, String> params) {
        String refusal = destructiveGuard(params, "delete_function");
        if (refusal != null) {
            return refusal;
        }
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required";
        }
        Function func = getFunctionForAddress(program, addr);
        if (func == null) {
            return "No function at or containing " + addr;
        }
        Address entry = func.getEntryPoint();
        String name = func.getName();
        boolean ok = inTransaction("Delete function via HTTP",
                prog -> prog.getFunctionManager().removeFunction(entry));
        if (!ok) {
            return "Failed to delete function " + name + " at " + entry;
        }
        return "Deleted function " + name + " at " + entry + ". Restore with /undo (name: "
                + trimToEmpty(program.getUndoName()) + ").";
    }

    private String createLabelAt(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required";
        }
        String name = trimToEmpty(firstNonEmpty(params, "name", "new_name", "newName"));
        if (name.isEmpty()) {
            return "name= is required";
        }
        boolean replace = !"false".equalsIgnoreCase(trimToEmpty(params.get("replace")));

        AtomicReference<String> failure = new AtomicReference<>();
        AtomicReference<String> finalName = new AtomicReference<>(name);
        boolean ok = inTransaction("Create label via HTTP", prog -> {
            try {
                SymbolTable symbols = prog.getSymbolTable();
                Symbol existing = symbols.getPrimarySymbol(addr);
                if (existing != null) {
                    if (!replace) {
                        failure.set("symbol '" + existing.getName()
                                + "' already exists; pass replace=true to rename it");
                        return false;
                    }
                    existing.setName(name, SourceType.USER_DEFINED);
                } else {
                    symbols.createLabel(addr, name, SourceType.USER_DEFINED);
                }
                Symbol created = symbols.getPrimarySymbol(addr);
                if (created != null) {
                    finalName.set(created.getName());
                }
                return true;
            } catch (Exception e) {
                failure.set(e.toString());
                return false;
            }
        });
        if (!ok) {
            return "Failed to label " + addr + ": " + trimToEmpty(failure.get());
        }
        return "Label '" + finalName.get() + "' set at " + addr + " (revert with /undo)";
    }

    private String listFunctionVariables(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "function_address= is required";
        }
        Function func = getFunctionForAddress(program, addr);
        if (func == null) {
            return "No function at or containing " + addr;
        }
        List<String> lines = new ArrayList<>();
        lines.add("Function " + func.getName() + " at " + func.getEntryPoint()
                + "  return=" + func.getReturnType().getName()
                + (func.hasVarArgs() ? "  (varargs)" : ""));
        for (Parameter param : func.getParameters()) {
            lines.add(String.format("param %-3d %-28s %-36s %s",
                    param.getOrdinal(), param.getName(), param.getDataType().getName(),
                    param.getVariableStorage()));
        }
        Variable[] locals = func.getLocalVariables();
        for (int i = 0; i < locals.length; i++) {
            Variable local = locals[i];
            lines.add(String.format("local %-3d %-28s %-36s %s",
                    i, local.getName(), local.getDataType().getName(),
                    local.getVariableStorage()));
        }
        if (lines.size() == 1) {
            lines.add("(no parameters or locals)");
        }
        return paginateList(lines, offset, limit);
    }

    private String dataTypeKind(DataType dt) {
        if (dt instanceof Structure) {
            return "struct";
        }
        if (dt instanceof Union) {
            return "union";
        }
        if (dt instanceof Enum) {
            return "enum";
        }
        if (dt instanceof TypeDef) {
            return "typedef";
        }
        if (dt instanceof Pointer) {
            return "pointer";
        }
        if (dt instanceof Array) {
            return "array";
        }
        if (dt instanceof FunctionDefinition) {
            return "funcdef";
        }
        if (dt instanceof BuiltIn) {
            return "builtin";
        }
        return dt.getClass().getSimpleName();
    }

    private String listDataTypes(String query, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        String needle = trimToEmpty(query).toLowerCase(Locale.ROOT);
        List<String> lines = new ArrayList<>();
        Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            String path = dt.getPathName();
            if (!needle.isEmpty() && !path.toLowerCase(Locale.ROOT).contains(needle)) {
                continue;
            }
            lines.add(String.format("%-56s %-10s len=%d", path, dataTypeKind(dt), dt.getLength()));
        }
        if (lines.isEmpty()) {
            return "No data types matching '" + trimToEmpty(query) + "'";
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String setCommentByType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required";
        }
        String type = trimToEmpty(params.get("type"));
        if (type.isEmpty()) {
            type = "eol";
        }
        int commentType;
        switch (type.toLowerCase(Locale.ROOT)) {
            case "plate":
                commentType = CodeUnit.PLATE_COMMENT;
                break;
            case "pre":
            case "decompiler":
                commentType = CodeUnit.PRE_COMMENT;
                break;
            case "post":
                commentType = CodeUnit.POST_COMMENT;
                break;
            case "repeatable":
            case "repeat":
                commentType = CodeUnit.REPEATABLE_COMMENT;
                break;
            case "eol":
            case "disassembly":
                commentType = CodeUnit.EOL_COMMENT;
                break;
            default:
                return "Unknown type '" + type + "'; use plate|pre|eol|post|repeatable";
        }
        String comment = params.get("comment");
        if (comment == null) {
            comment = "";
        }
        boolean ok = setCommentAtAddress(params.get("address"), comment, commentType,
                "Set " + type + " comment");
        if (!ok) {
            return "Failed to set " + type + " comment at " + addr;
        }
        return "Comment (" + type.toLowerCase(Locale.ROOT) + ") "
                + (comment.isEmpty() ? "cleared" : "set") + " at " + addr;
    }

    private String listBasicBlocks(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "address= is required";
        }
        Function func = getFunctionForAddress(program, addr);
        if (func == null) {
            return "No function at or containing " + addr;
        }
        List<String> lines = new ArrayList<>();
        lines.add("Basic blocks of " + func.getName() + " at " + func.getEntryPoint());
        try {
            CodeBlockModel model = new BasicBlockModel(program);
            TaskMonitor monitor = new ConsoleTaskMonitor();
            CodeBlockIterator blocks = model.getCodeBlocksContaining(func.getBody(), monitor);
            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                List<String> destinations = new ArrayList<>();
                CodeBlockReferenceIterator refs = block.getDestinations(monitor);
                while (refs.hasNext()) {
                    CodeBlockReference ref = refs.next();
                    Address dest = ref.getDestinationAddress();
                    Function target = program.getFunctionManager().getFunctionAt(dest);
                    destinations.add(dest + (target != null ? " (" + target.getName() + ")" : ""));
                }
                lines.add(String.format("%s-%s  (%d dest)  -> %s",
                        block.getMinAddress(), block.getMaxAddress(),
                        destinations.size(),
                        destinations.isEmpty() ? "(none)" : String.join(", ", destinations)));
            }
        } catch (Exception e) {
            return "Failed to compute basic blocks: " + e.getMessage();
        }
        return paginateList(lines, offset, limit);
    }

    private String callGraph(String addressStr, int depth, String direction) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "address= is required";
        }
        Function start = getFunctionForAddress(program, addr);
        if (start == null) {
            return "No function at or containing " + addr;
        }
        depth = Math.max(1, Math.min(depth, 4));
        String dir = trimToEmpty(direction);
        if (dir.isEmpty()) {
            dir = "both";
        }
        dir = dir.toLowerCase(Locale.ROOT);

        List<String> lines = new ArrayList<>();
        lines.add("Call graph for " + start.getName() + " at " + start.getEntryPoint()
                + " (depth=" + depth + ", direction=" + dir + ")");
        TaskMonitor monitor = new ConsoleTaskMonitor();
        if (!dir.equals("callers")) {
            lines.add("callees:");
            collectCallTree(start, depth, monitor, true, lines, 0, new HashSet<>());
        }
        if (!dir.equals("callees")) {
            lines.add("callers:");
            collectCallTree(start, depth, monitor, false, lines, 0, new HashSet<>());
        }
        return String.join("\n", lines);
    }

    private void collectCallTree(Function func, int depth, TaskMonitor monitor, boolean callees,
            List<String> lines, int level, Set<String> seen) {
        if (level >= depth) {
            return;
        }
        String key = (callees ? "c:" : "r:") + func.getEntryPoint();
        if (!seen.add(key)) {
            return;
        }
        Set<Function> next = callees
                ? func.getCalledFunctions(monitor)
                : func.getCallingFunctions(monitor);
        if (next == null) {
            return;
        }
        List<Function> sorted = new ArrayList<>(next);
        sorted.sort(Comparator.comparing(Function::getName));
        for (Function target : sorted) {
            lines.add("  ".repeat(level + 1) + target.getName() + " @ " + target.getEntryPoint());
            collectCallTree(target, depth, monitor, callees, lines, level + 1, seen);
        }
    }

    private String searchBytes(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        String hex = trimToEmpty(firstNonEmpty(params, "hex", "bytes"));
        hex = hex.replaceAll("(?i)0x", "").replaceAll("[\\s,_-]", "");
        if (hex.isEmpty() || hex.length() % 2 != 0 || !hex.matches("[0-9a-fA-F]+")) {
            return "hex= must be an even-length hex byte string, e.g. hex=1eff2f01";
        }
        byte[] pattern = new byte[hex.length() / 2];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        Address start = parseAddress(program, params.get("address"));
        if (start == null) {
            start = program.getMinAddress();
        }
        int limit = Math.max(1, Math.min(parseIntOrDefault(params.get("limit"), 16), 200));
        Address max = program.getMaxAddress();
        List<String> hits = new ArrayList<>();
        Address cursor = start;
        try {
            while (hits.size() < limit) {
                Address found = program.getMemory().findBytes(cursor, max, pattern, null, true,
                        new ConsoleTaskMonitor());
                if (found == null) {
                    break;
                }
                hits.add(found.toString());
                cursor = found.add(1);
            }
        } catch (Exception e) {
            return "Search failed: " + e.getMessage();
        }
        if (hits.isEmpty()) {
            return "No matches for " + hex + " from " + start;
        }
        StringBuilder sb = new StringBuilder("Matches for ").append(hex)
                .append(" (").append(hits.size());
        if (hits.size() >= limit) {
            sb.append(", limit reached");
        }
        sb.append("):\n");
        for (String hit : hits) {
            sb.append(hit).append("\n");
        }
        sb.append("Inspect with /disassemble, /data or /xrefs_from.");
        return sb.toString();
    }

    private String addBookmark(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        Address addr = parseAddress(program, params.get("address"));
        if (addr == null) {
            return "address= is required";
        }
        String type = trimToEmpty(params.get("type"));
        if (type.isEmpty()) {
            type = BookmarkType.NOTE;
        }
        String category = trimToEmpty(params.get("category"));
        if (category.isEmpty()) {
            category = "GhidraMCP";
        }
        String comment = params.get("comment") == null ? "" : params.get("comment");
        final String bookmarkType = type;
        final String bookmarkCategory = category;
        AtomicReference<String> failure = new AtomicReference<>();
        boolean ok = inTransaction("Add bookmark via HTTP", prog -> {
            BookmarkManager manager = prog.getBookmarkManager();
            if (manager.getBookmarkType(bookmarkType) == null) {
                List<String> available = new ArrayList<>();
                for (BookmarkType known : manager.getBookmarkTypes()) {
                    available.add(known.getTypeString());
                }
                failure.set("unknown bookmark type '" + bookmarkType
                        + "'; available: " + String.join(", ", available));
                return false;
            }
            manager.setBookmark(addr, bookmarkType, bookmarkCategory, comment);
            return true;
        });
        if (!ok) {
            return "Failed to bookmark " + addr + ": " + trimToEmpty(failure.get());
        }
        return "Bookmark [" + bookmarkType + "] at " + addr + " (category " + category + ")";
    }

    private String listBookmarks(String type, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        BookmarkManager manager = program.getBookmarkManager();
        Iterator<Bookmark> it = trimToEmpty(type).isEmpty()
                ? manager.getBookmarksIterator()
                : manager.getBookmarksIterator(type);
        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Bookmark bookmark = it.next();
            lines.add(String.format("%s [%s] %s: %s",
                    bookmark.getAddress(), bookmark.getTypeString(),
                    bookmark.getCategory(), bookmark.getComment()));
        }
        if (lines.isEmpty()) {
            return "No bookmarks" + (trimToEmpty(type).isEmpty() ? "" : " of type '" + type + "'");
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String undoRedo(boolean undo, int steps) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        final int maxSteps = Math.max(1, Math.min(steps, 20));
        List<String> names = new ArrayList<>();
        AtomicReference<String> failure = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                for (int i = 0; i < maxSteps; i++) {
                    if (undo ? !program.canUndo() : !program.canRedo()) {
                        break;
                    }
                    String name = undo ? program.getUndoName() : program.getRedoName();
                    try {
                        if (undo) {
                            program.undo();
                        } else {
                            program.redo();
                        }
                        names.add(name == null ? "(unnamed)" : name);
                    } catch (IOException e) {
                        failure.set(e.toString());
                        break;
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to run " + (undo ? "undo" : "redo") + ": " + e;
        }
        if (failure.get() != null) {
            return "Failed to " + (undo ? "undo" : "redo") + ": " + failure.get()
                    + (names.isEmpty() ? "" : " (after " + names.size() + " step(s))");
        }
        if (names.isEmpty()) {
            return undo ? "Nothing to undo" : "Nothing to redo";
        }
        return (undo ? "Undid " : "Redid ") + names.size() + " transaction(s): "
                + String.join(" | ", names);
    }

    private String undoState() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("canUndo=").append(program.canUndo())
                .append("  undoName=").append(trimToEmpty(program.getUndoName())).append("\n");
        sb.append("canRedo=").append(program.canRedo())
                .append("  redoName=").append(trimToEmpty(program.getRedoName())).append("\n");
        List<String> undos = program.getAllUndoNames();
        List<String> redos = program.getAllRedoNames();
        sb.append("undo depth=").append(undos.size()).append(":");
        for (String name : last(undos, 15)) {
            sb.append("\n  - ").append(name);
        }
        sb.append("\nredo depth=").append(redos.size()).append(":");
        for (String name : last(redos, 15)) {
            sb.append("\n  - ").append(name);
        }
        return sb.toString();
    }

    private String runBatch(String body) {
        if (trimToEmpty(body).isEmpty()) {
            return "Batch body must be JSON: {\"operations\":[{\"op\":\"...\"}],\"save\":true}";
        }
        JsonElement root;
        try {
            root = JsonParser.parseString(body);
        } catch (RuntimeException e) {
            return "Invalid JSON: " + e.getMessage();
        }
        boolean save = true;
        JsonArray operations;
        if (root.isJsonArray()) {
            operations = root.getAsJsonArray();
        } else if (root.isJsonObject()) {
            JsonObject object = root.getAsJsonObject();
            JsonElement saveElement = object.get("save");
            if (saveElement != null && !saveElement.isJsonNull()) {
                try {
                    save = saveElement.getAsBoolean();
                } catch (RuntimeException ignored) {
                    // keep the default
                }
            }
            JsonElement opsElement = object.get("operations");
            if (opsElement == null || !opsElement.isJsonArray()) {
                return "Missing 'operations' array";
            }
            operations = opsElement.getAsJsonArray();
        } else {
            return "Batch body must be a JSON object with an 'operations' array";
        }

        List<String> results = new ArrayList<>();
        int index = 0;
        for (JsonElement element : operations) {
            index++;
            if (!element.isJsonObject()) {
                results.add(index + ". (skipped non-object operation)");
                continue;
            }
            JsonObject operation = element.getAsJsonObject();
            String name = operation.has("op") ? trimToEmpty(operation.get("op").getAsString()) : "";
            if (name.isEmpty()) {
                results.add(index + ". (missing 'op')");
                continue;
            }
            Map<String, String> params = new LinkedHashMap<>();
            for (Map.Entry<String, JsonElement> entry : operation.entrySet()) {
                if ("op".equals(entry.getKey())) {
                    continue;
                }
                JsonElement value = entry.getValue();
                params.put(entry.getKey(), value.isJsonPrimitive()
                        ? value.getAsString()
                        : value.toString());
            }
            String result;
            try {
                result = dispatchBatchOperation(name, params);
            } catch (RuntimeException e) {
                result = "Failed: " + e;
            }
            results.add(index + ". " + name + ": " + oneLine(result));
        }
        if (save) {
            results.add("save_program: " + (saveCurrentProgram() ? "ok" : "FAILED"));
        }
        return String.join("\n", results);
    }

    private String dispatchBatchOperation(String rawName, Map<String, String> params) {
        String name = rawName.startsWith("/") ? rawName.substring(1) : rawName;
        switch (name.toLowerCase(Locale.ROOT)) {
            case "disassemble":
                return disassembleAt(params);
            case "undefine":
                return undefineRange(params);
            case "create_data":
                return createDataAt(params);
            case "set_data_type": {
                if (!params.containsKey("type")) {
                    params.put("type", firstNonEmpty(params, "new_type", "data_type"));
                }
                params.putIfAbsent("overwrite", "true");
                return createDataAt(params);
            }
            case "delete_function":
                return deleteFunctionAt(params);
            case "create_label":
                return createLabelAt(params);
            case "rename_data":
                return renameDataAtAddress(
                        firstNonEmpty(params, "address", "new_address"),
                        firstNonEmpty(params, "new_name", "newName"));
            case "rename_function":
                return renameFunctionByAddress(
                        firstNonEmpty(params, "address", "function_address"),
                        firstNonEmpty(params, "name", "new_name"))
                                ? "Function renamed"
                                : "Failed to rename function";
            case "create_function": {
                String address = firstNonEmpty(params, "address", "function_address");
                String newName = firstNonEmpty(params, "name", "new_name");
                boolean disassembleFirst = !"false".equalsIgnoreCase(
                        trimToEmpty(params.get("disassemble_first")));
                return createFunctionAt(address, newName, disassembleFirst)
                        ? "Function created"
                        : "Failed to create function";
            }
            case "set_comment":
                return setCommentByType(params);
            case "search_bytes":
                return searchBytes(params);
            case "bookmark":
                return addBookmark(params);
            default:
                return "Unknown op '" + rawName + "'";
        }
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonResponse(HttpExchange exchange, String jsonResponse) throws IOException {
        byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (activeInstances.containsKey(this.currentPort)) {
            activeInstances.remove(this.currentPort);
        }
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server on port " + this.currentPort + "...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
