package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Optional MODEGY root DEX redivision. Merge the shell, plain SDK classes and
 * junk classes into one classes.dex; never touch encrypted MODEGY_DATA.zip.
 * Fails closed on duplicate types, dexlib2-fragile packages or DEX index limits.
 */
public final class ModegyRootDexRedivision {
    private ModegyRootDexRedivision() {}

    public static int merge(File apkRoot) throws IOException {
        if (apkRoot == null || !apkRoot.isDirectory()) {
            throw new IOException("MODEGY_DEX_ROOT_INVALID");
        }
        List<File> inputs = new ArrayList<>();
        File main = new File(apkRoot, "classes.dex");
        if (!main.isFile()) {
            throw new IOException("MODEGY_DEX_PRIMARY_MISSING");
        }
        inputs.add(main);
        int i = 2;
        while (new File(apkRoot, "classes" + i + ".dex").isFile()) {
            inputs.add(new File(apkRoot, "classes" + i + ".dex"));
            i++;
        }
        File[] all = apkRoot.listFiles((d, n) -> n.matches("classes[0-9]+\\.dex"));
        if (all != null && all.length != inputs.size() - 1) {
            throw new IOException("MODEGY_DEX_NONCONTIGUOUS");
        }
        if (inputs.size() == 1) {
            return 1;
        }

        Set<String> before = new HashSet<>();
        DexPool merged = new DexPool(Opcodes.getDefault());
        for (File dexPath : inputs) {
            DexBackedDexFile dex;
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dexPath))) {
                dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            }
            for (ClassDef clazz : dex.getClasses()) {
                String descriptor = clazz.getType();
                if (!before.add(descriptor)) {
                    throw new IOException("MODEGY_DEX_DUPLICATE_CLASS: " + descriptor);
                }
                // DexPool rewriting these classes is known to break some apps.
                if (DexClassSplit.isDexPoolFragileType(descriptor)) {
                    throw new IOException("MODEGY_DEX_MERGE_UNSAFE_CLASS: " + descriptor);
                }
                merged.internClass(clazz);
            }
        }

        Path temp = Files.createTempFile(apkRoot.toPath(), ".modegy-root-", ".dex");
        try {
            merged.writeTo(new FileDataStore(temp.toFile()));
            byte[] header = new byte[112];
            try (FileInputStream input = new FileInputStream(temp.toFile())) {
                if (input.read(header) != header.length) {
                    throw new IOException("MODEGY_DEX_MERGE_HEADER");
                }
            }
            if (header[0] != 'd' || header[1] != 'e' || header[2] != 'x'
                    || header[3] != '\n') {
                throw new IOException("MODEGY_DEX_MERGE_MAGIC");
            }
            ByteBuffer h = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
            // A single DEX has 16-bit reference indices. Never silently
            // generate a DEX needing jumbo/overflowing methods or field refs.
            for (int offset : new int[]{56, 64, 72, 80, 88, 96}) {
                int count = h.getInt(offset);
                if (count < 0 || count > 65535) {
                    throw new IOException("MODEGY_DEX_SINGLE_FILE_LIMIT_" + offset + ": " + count);
                }
            }
            Set<String> after = new HashSet<>();
            DexBackedDexFile candidate;
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(temp.toFile()))) {
                candidate = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            }
            for (ClassDef clazz : candidate.getClasses()) {
                if (!after.add(clazz.getType())) {
                    throw new IOException("MODEGY_DEX_OUTPUT_DUPLICATE");
                }
            }
            if (!after.equals(before)) {
                throw new IOException("MODEGY_DEX_CLASS_SET_CHANGED");
            }
            Files.move(temp, main.toPath(), StandardCopyOption.REPLACE_EXISTING);
            for (int j = 1; j < inputs.size(); j++) {
                if (!inputs.get(j).delete()) {
                    throw new IOException("MODEGY_DEX_SECONDARY_DELETE_FAILED");
                }
            }
            System.out.println("MODEGY DEX redivision: " + inputs.size()
                    + " root DEX files -> classes.dex; classes=" + before.size());
            return inputs.size();
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
