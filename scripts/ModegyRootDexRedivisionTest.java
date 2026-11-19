package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ModegyRootDexRedivisionTest {
    @TempDir Path tmp;

    private static ImmutableClassDef klass(String type) {
        ImmutableMethod init = new ImmutableMethod(
                type, "<init>", Collections.emptyList(), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null, null, null);
        return new ImmutableClassDef(type, AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", null, null, null, null,
                Collections.singletonList(init));
    }

    private static void writeDex(File file, String... descriptors) throws Exception {
        DexPool pool = new DexPool(Opcodes.getDefault());
        for (String type : descriptors) {
            pool.internClass(klass(type));
        }
        pool.writeTo(new FileDataStore(file));
    }

    private static Set<String> types(File file) throws Exception {
        Set<String> out = new HashSet<>();
        try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(file))) {
            for (var c : DexBackedDexFile.fromInputStream(Opcodes.getDefault(), input).getClasses()) {
                out.add(c.getType());
            }
        }
        return out;
    }

    @Test void acceptsLargeStringTableButRejectsActualDexReferenceOverflows() throws Exception {
        byte[] header = new byte[112];
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        buf.putInt(56, 70000); // string_ids_size: jumbo const-string is legal
        ModegyRootDexRedivision.validateDexReferences(header);
        for (int offset : new int[]{64, 72, 80, 88, 96}) {
            buf.putInt(offset, 65536);
            java.io.IOException error = assertThrows(java.io.IOException.class,
                    () -> ModegyRootDexRedivision.validateDexReferences(header));
            assertTrue(error.getMessage().contains("MODEGY_DEX_SINGLE_FILE_LIMIT_" + offset));
            buf.putInt(offset, 0);
        }
        buf.putInt(56, -1);
        assertThrows(java.io.IOException.class,
                () -> ModegyRootDexRedivision.validateDexReferences(header));
        assertThrows(java.io.IOException.class,
                () -> ModegyRootDexRedivision.validateDexReferences(new byte[100]));
    }

    @Test void mergesRootDexOnlyAndPreservesAllClasses() throws Exception {
        writeDex(tmp.resolve("classes.dex").toFile(), "Lcom/modegypro/protection/shell/ModegyRuntime;");
        writeDex(tmp.resolve("classes2.dex").toFile(), "Lpro0/egy;");
        writeDex(tmp.resolve("classes3.dex").toFile(), "Lcom/modegypro/protection/decoy/JunkClass;");
        Files.write(tmp.resolve("MODEGY_DATA.zip"), new byte[]{1, 2, 3, 4});
        assertEquals(3, ModegyRootDexRedivision.merge(tmp.toFile()));
        assertFalse(Files.exists(tmp.resolve("classes2.dex")));
        assertFalse(Files.exists(tmp.resolve("classes3.dex")));
        assertArrayEquals(new byte[]{1, 2, 3, 4}, Files.readAllBytes(tmp.resolve("MODEGY_DATA.zip")));
        assertEquals(Set.of("Lcom/modegypro/protection/shell/ModegyRuntime;",
                            "Lpro0/egy;", "Lcom/modegypro/protection/decoy/JunkClass;"),
                     types(tmp.resolve("classes.dex").toFile()));
    }

    @Test void duplicateClassesFailWithoutModifyingPrimaryDex() throws Exception {
        writeDex(tmp.resolve("classes.dex").toFile(), "Lpro0/egy;");
        writeDex(tmp.resolve("classes2.dex").toFile(), "Lpro0/egy;");
        byte[] original = Files.readAllBytes(tmp.resolve("classes.dex"));
        assertThrows(java.io.IOException.class,
                () -> ModegyRootDexRedivision.merge(tmp.toFile()));
        assertArrayEquals(original, Files.readAllBytes(tmp.resolve("classes.dex")));
        assertTrue(Files.exists(tmp.resolve("classes2.dex")));
    }

    @Test void fragileComposeClassFailsClosed() throws Exception {
        writeDex(tmp.resolve("classes.dex").toFile(), "Lcom/modegypro/protection/shell/ModegyRuntime;");
        writeDex(tmp.resolve("classes2.dex").toFile(), "Landroidx/compose/Foo;");
        assertThrows(java.io.IOException.class,
                () -> ModegyRootDexRedivision.merge(tmp.toFile()));
        assertTrue(Files.exists(tmp.resolve("classes2.dex")));
    }
}
