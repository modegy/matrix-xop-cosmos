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
 * Adaptive root DEX redivision after shell embedding.
 * Android multidex is retained when a safe single root DEX cannot be produced.
 * The encrypted PDX1 MODEGY_DATA.zip is never read or rewritten.
 * Original large/fragile root DEX files are passed through byte-for-byte.
 */
public final class ModegyRootDexRedivision {
    private static final long MAX_REWRITE_SOURCE_BYTES = 24L * 1024 * 1024;
    private static final long MAX_GROUP_SOURCE_BYTES = 16L * 1024 * 1024;
    private static final int MAX_GROUP_CLASSES = 1400;
    private ModegyRootDexRedivision() {}

    private static String name(int index) {
        return index == 1 ? "classes.dex" : "classes" + index + ".dex";
    }

    static void validateDexReferences(byte[] header) throws IOException {
        if (header == null || header.length < 112)
            throw new IOException("MODEGY_DEX_MERGE_HEADER");
        ByteBuffer h = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int strings = h.getInt(56);
        // DEX string IDs support jumbo indices. Other reference sections do not.
        if (strings < 0) throw new IOException("MODEGY_DEX_INVALID_STRING_COUNT");
        for (int offset : new int[]{64, 72, 80, 88, 96}) {
            int count = h.getInt(offset);
            if (count < 0 || count > 65535)
                throw new IOException("MODEGY_DEX_SINGLE_FILE_LIMIT_" + offset + ": " + count);
        }
    }

    private static void inspectWrittenDex(Path path, List<ClassDef> original)
            throws IOException {
        byte[] header = new byte[112];
        try (FileInputStream in = new FileInputStream(path.toFile())) {
            if (in.read(header) != 112 || header[0] != 'd' || header[1] != 'e'
                    || header[2] != 'x' || header[3] != '\n')
                throw new IOException("MODEGY_DEX_MERGE_MAGIC");
        }
        validateDexReferences(header);
        Set<String> expected = new HashSet<>();
        for (ClassDef c : original)
            if (!expected.add(c.getType()))
                throw new IOException("MODEGY_DEX_DUPLICATE_CLASS");
        Set<String> found = new HashSet<>();
        try (BufferedInputStream in =
                 new BufferedInputStream(new FileInputStream(path.toFile()))) {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            for (ClassDef c : dex.getClasses())
                if (!found.add(c.getType()))
                    throw new IOException("MODEGY_DEX_OUTPUT_DUPLICATE");
        }
        if (!found.equals(expected))
            throw new IOException("MODEGY_DEX_CLASS_SET_CHANGED");
    }

    /**
     * Write a bounded batch. If the combined references overflow, split at a
     * class boundary and keep multiple root DEX files rather than failing the
     * whole APK. Never change any class definition or method implementation.
     */
    private static int writeGroup(List<ClassDef> classes, Path staged, int next)
            throws IOException {
        if (classes.isEmpty()) return next;
        Path candidate = staged.resolve(name(next));
        try {
            DexPool pool = new DexPool(Opcodes.getDefault());
            for (ClassDef c : classes) pool.internClass(c);
            pool.writeTo(new FileDataStore(candidate.toFile()));
            inspectWrittenDex(candidate, classes);
            return next + 1;
        } catch (IOException e) {
            Files.deleteIfExists(candidate);
            if (!e.getMessage().startsWith("MODEGY_DEX_SINGLE_FILE_LIMIT_")
                    || classes.size() == 1) throw e;
            int halfway = classes.size() / 2;
            next = writeGroup(classes.subList(0, halfway), staged, next);
            return writeGroup(classes.subList(halfway, classes.size()), staged, next);
        }
    }

    private static int flush(List<ClassDef> pending, Path staged, int index)
            throws IOException {
        if (pending.isEmpty()) return index;
        index = writeGroup(pending, staged, index);
        pending.clear();
        return index;
    }

    private static void validateOriginalDexClassSet(File file, Set<String> global)
            throws IOException {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file))) {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            for (ClassDef c : dex.getClasses())
                if (!global.add(c.getType()))
                    throw new IOException("MODEGY_DEX_DUPLICATE_CLASS: " + c.getType());
        }
    }

    /**
     * Attempt one root DEX before bounded redivision. The old 1400-class
     * batching threshold is a memory-safety heuristic, NOT a DEX format
     * restriction. Retain adaptive multidex only when one DEX is unsafe.
     */
    private static boolean trySingleDex(List<File> original, Path staged) throws IOException {
        long totalSourceBytes = 0;
        for (File file : original) {
            if (file.length() > MAX_REWRITE_SOURCE_BYTES) return false;
            totalSourceBytes += file.length();
            if (totalSourceBytes > MAX_GROUP_SOURCE_BYTES) return false;
        }
        List<ClassDef> classes = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (File file : original) {
            DexBackedDexFile dex;
            try (BufferedInputStream in =
                    new BufferedInputStream(new FileInputStream(file))) {
                dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
            }
            for (ClassDef type : dex.getClasses()) {
                if (!seen.add(type.getType()))
                    throw new IOException("MODEGY_DEX_DUPLICATE_CLASS: " + type.getType());
                // Keep known DexPool-fragile namespaces byte-for-byte in
                // the original adaptive multidex path.
                if (DexClassSplit.isDexPoolFragileType(type.getType()))
                    return false;
                classes.add(type);
            }
        }
        if (classes.isEmpty()) return false;
        int next = writeGroup(classes, staged, 1);
        if (next != 2) {
            // A genuine DEX reference overflow caused a safe split.
            for (int i = 1; i < next; i++)
                Files.deleteIfExists(staged.resolve(name(i)));
            return false;
        }
        // The candidate passed reference-limit and exact class-set checks.
        Files.move(staged.resolve(name(1)), original.get(0).toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        for (int i = 1; i < original.size(); i++)
            Files.deleteIfExists(original.get(i).toPath());
        System.out.println("MODEGY adaptive root DEX redivision: input="
                + original.size() + " output=1 single_safe=true");
        return true;
    }

    public static int merge(File apkRoot) throws IOException {
        if (apkRoot == null || !apkRoot.isDirectory())
            throw new IOException("MODEGY_DEX_ROOT_INVALID");
        List<File> original = new ArrayList<>();
        for (int i = 1; ; i++) {
            File file = new File(apkRoot, name(i));
            if (!file.isFile()) {
                if (i == 1) throw new IOException("MODEGY_DEX_PRIMARY_MISSING");
                break;
            }
            original.add(file);
        }
        File[] all = apkRoot.listFiles((d, n) -> n.matches("classes[2-9][0-9]*\\.dex|classes[1-9][0-9]+\\.dex"));
        if (all != null && all.length != original.size() - 1)
            throw new IOException("MODEGY_DEX_NONCONTIGUOUS");
        if (original.size() == 1) return 1;

        Path staged = Files.createTempDirectory(apkRoot.toPath(), ".modegy-redivision-");
        // Prefer a validated single DEX for small, non-fragile outputs.
        try {
            if (trySingleDex(original, staged)) return 1;
        } finally {
            File[] trial = staged.toFile().listFiles();
            if (trial != null)
                for (File f : trial) Files.deleteIfExists(f.toPath());
        }
        int next = 1;
        int copied = 0;
        List<ClassDef> pending = new ArrayList<>();
        Set<String> seenInGroup = new HashSet<>();
        Set<String> seenOverall = new HashSet<>();
        long groupBytes = 0;
        try {
            for (File file : original) {
                // Large inputs are already valid DEX files. Rewriting their
                // methods via DexPool causes excessive memory use and risks
                // breaking obfuscated/Compose instructions.
                if (file.length() > MAX_REWRITE_SOURCE_BYTES) {
                    validateOriginalDexClassSet(file, seenOverall);
                    next = flush(pending, staged, next);
                    seenInGroup.clear(); groupBytes = 0;
                    Files.copy(file.toPath(), staged.resolve(name(next++)));
                    copied++;
                    continue;
                }
                DexBackedDexFile dex;
                try (BufferedInputStream in =
                         new BufferedInputStream(new FileInputStream(file))) {
                    dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in);
                }
                boolean fragile = false;
                for (ClassDef c : dex.getClasses()) {
                    if (DexClassSplit.isDexPoolFragileType(c.getType())) {
                        fragile = true;
                        break;
                    }
                }
                if (fragile) {
                    validateOriginalDexClassSet(file, seenOverall);
                    next = flush(pending, staged, next);
                    seenInGroup.clear(); groupBytes = 0;
                    Files.copy(file.toPath(), staged.resolve(name(next++)));
                    copied++;
                    continue;
                }
                if (groupBytes + file.length() > MAX_GROUP_SOURCE_BYTES) {
                    next = flush(pending, staged, next);
                    seenInGroup.clear(); groupBytes = 0;
                }
                for (ClassDef c : dex.getClasses()) {
                    if (!seenOverall.add(c.getType()))
                        throw new IOException("MODEGY_DEX_DUPLICATE_CLASS: " + c.getType());
                    if (pending.size() >= MAX_GROUP_CLASSES ||
                            seenInGroup.contains(c.getType())) {
                        next = flush(pending, staged, next);
                        seenInGroup.clear(); groupBytes = 0;
                    }
                    pending.add(c);
                    seenInGroup.add(c.getType());
                }
                groupBytes += file.length();
            }
            next = flush(pending, staged, next);
            int count = next - 1;
            if (count < 1) throw new IOException("MODEGY_DEX_OUTPUT_EMPTY");
            // No changes to the APK root until every output is generated and
            // validated. The packer operates on a disposable unpack directory.
            for (int i = 1; i <= count; i++)
                Files.move(staged.resolve(name(i)),
                        new File(apkRoot, name(i)).toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            for (int i = count + 1; i <= original.size(); i++)
                Files.deleteIfExists(new File(apkRoot, name(i)).toPath());
            System.out.println("MODEGY adaptive root DEX redivision: input=" +
                    original.size() + " output=" + count +
                    " untouched_large_or_fragile=" + copied);
            return count;
        } finally {
            File[] leftovers = staged.toFile().listFiles();
            if (leftovers != null)
                for (File f : leftovers) Files.deleteIfExists(f.toPath());
            Files.deleteIfExists(staged);
        }
    }
}
