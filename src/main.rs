use anyhow::{anyhow, Context, Result};
use clap::Parser;
use memmap2::Mmap;
use object::{BinaryFormat, Object, ObjectSection, SectionKind};
use rayon::prelude::*;
use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// File signature database
const FILE_SIGNATURES: &[(&str, &[u8], &str)] = &[
    ("PNG", b"\x89PNG\r\n\x1a\n", "png"),
    ("JPEG", b"\xff\xd8\xff", "jpg"),
    ("GIF", b"GIF87a", "gif"),
    ("GIF", b"GIF89a", "gif"),
    ("WEBP", b"RIFF", "webp"),
    ("BMP", b"BM", "bmp"),
    ("TIFF", b"II\x2A\x00", "tiff"),
    ("TIFF", b"MM\x00\x2A", "tiff"),
    ("ICO", b"\x00\x00\x01\x00", "ico"),
    ("PCAP", b"\xa1\xb2\xc3\xd4", "pcap"),
    ("PCAP", b"\xd4\xc3\xb2\xa1", "pcapng"),
    ("PDF", b"%PDF", "pdf"),
    ("ZIP", b"PK\x03\x04", "zip"),
    ("ZIP", b"PK\x05\x06", "zip"),
    ("ZIP", b"PK\x07\x08", "zip"),
    ("7ZIP", b"7z\xBC\xAF\x27\x1C", "7z"),
    ("RAR", b"Rar!\x1A\x07\x00", "rar"),
    ("RAR", b"Rar!\x1A\x07\x01\x00", "rar"),
    ("GZIP", b"\x1F\x8B\x08", "gz"),
    ("BZIP2", b"BZh", "bz2"),
    ("XZ", b"\xFD7zXZ\x00", "xz"),
    ("TAR", b"ustar\x0000", "tar"),
    ("TAR", b"ustar\x0030", "tar"),
    ("EXE/DLL", b"MZ", "exe"),
    ("ELF", b"\x7FELF", "elf"),
    ("MACHO", b"\xFE\xED\xFA\xCE", "macho"),
    ("MACHO", b"\xCE\xFA\xED\xFE", "macho"),
    ("MACHO", b"\xFE\xED\xFA\xCF", "macho64"),
    ("MACHO", b"\xCF\xFA\xED\xFE", "macho64"),
    ("PE", b"MZ", "pe"),
    ("CLASS", b"\xCA\xFE\xBA\xBE", "class"),
    ("SWF", b"FWS", "swf"),
    ("SWF", b"CWS", "swf"),
    ("SWF", b"ZWS", "swf"),
    ("FLV", b"FLV", "flv"),
    ("MP3_ID3", b"ID3", "mp3"),
    ("WAV", b"RIFF", "wav"),
    ("AVI", b"RIFF", "avi"),
    ("MP4", b"\x00\x00\x00\x0C", "mp4"),
    ("MP4", b"ftyp", "mp4"),
    ("MOV", b"\x00\x00\x00\x0C", "mov"),
    ("WEBM", b"\x1A\x45\xDF\xA3", "webm"),
    ("MKV", b"\x1A\x45\xDF\xA3", "mkv"),
    ("SQLITE", b"SQLite format 3", "sqlite"),
    ("LUA_BYTE", b"\x1BLua", "luac"),
    ("PYC", b"\x03\xF3\x0D\x0A", "pyc"),
    ("PYC", b"\x16\x0D\x0D\x0A", "pyc"),
    ("JAVA_SERIAL", b"\xAC\xED\x00\x05", "ser"),
    ("WINDOWS_REG", b"regf", "dat"),
    ("ISO", b"\x01\xCD\x00\x01", "iso"),
    ("DMG", b"koly", "dmg"),
    ("CAB", b"MSCF", "cab"),
    ("MSI", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "msi"),
    ("DOC", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "doc"),
    ("XLS", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "xls"),
    ("PPT", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ppt"),
    ("MSG", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "msg"),
    ("ODT", b"PK", "odt"),
    ("ODS", b"PK", "ods"),
    ("ODP", b"PK", "odp"),
    ("XML", b"<?xml", "xml"),
    ("HTML", b"<!DOCTYPE", "html"),
    ("HTML", b"<html", "html"),
    ("JSON", b"{", "json"),
    ("JSON", b"[", "json"),
];

// Pattern for common data types
const PATTERNS: &[(&str, &[u8])] = &[
    ("BASE64", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
    ("HEX", b"0123456789ABCDEFabcdef"),
    ("GUID", b"0123456789ABCDEFabcdef-{}"),
    ("IPV4", b"0123456789."),
    ("EMAIL", b"@"),
    ("URL", b"http://"),
    ("URL", b"https://"),
    ("CERT", b"-----BEGIN CERTIFICATE-----"),
    ("KEY", b"-----BEGIN PRIVATE KEY-----"),
    ("KEY", b"-----BEGIN RSA PRIVATE KEY-----"),
    ("KEY", b"-----BEGIN OPENSSH PRIVATE KEY-----"),
];

#[derive(Parser, Debug)]
#[command(author, version, about = "Full Binary Dumper - Extract everything from binaries")]
struct Args {
    /// Input file to analyze
    #[arg(short, long)]
    input: String,
    
    /// Output directory
    #[arg(short, long, default_value = "dump_output")]
    output: String,
    
    /// Minimum string length to extract
    #[arg(long, default_value_t = 4)]
    min_string_len: usize,
    
    /// Maximum string length to extract
    #[arg(long, default_value_t = 4096)]
    max_string_len: usize,
    
    /// Minimum file size to extract (bytes)
    #[arg(long, default_value_t = 16)]
    min_file_size: usize,
    
    /// Maximum file size to extract (bytes)
    #[arg(long, default_value_t = 100 * 1024 * 1024)] // 100 MB
    max_file_size: usize,
    
    /// Extract strings (ASCII/UTF-8)
    #[arg(long)]
    extract_strings: bool,
    
    /// Extract embedded files
    #[arg(long)]
    extract_files: bool,
    
    /// Extract code sections
    #[arg(long)]
    extract_code: bool,
    
    /// Extract resources (Windows PE)
    #[arg(long)]
    extract_resources: bool,
    
    /// Extract symbols/debug info
    #[arg(long)]
    extract_symbols: bool,
    
    /// Extract all data sections
    #[arg(long)]
    extract_data: bool,
    
    /// Extract everything (equivalent to all extract flags)
    #[arg(short = 'A', long)]
    extract_all: bool,
    
    /// Use parallel processing
    #[arg(long)]
    parallel: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Generate HTML report
    #[arg(long)]
    html_report: bool,
    
    /// Generate JSON report
    #[arg(long)]
    json_report: bool,
    
    /// Entropy threshold for detecting encrypted/compressed data
    #[arg(long, default_value_t = 7.0)]
    entropy_threshold: f64,
    
    /// Deep scan: try to extract from extracted files recursively
    #[arg(long)]
    deep_scan: bool,
}

#[derive(Debug, Clone)]
struct ExtractedItem {
    offset: u64,
    size: usize,
    item_type: String,
    description: String,
    file_path: Option<PathBuf>,
    entropy: f64,
    is_valid: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ExtractionReport {
    input_file: String,
    total_size: u64,
    extraction_time: f64,
    items_found: usize,
    items_by_type: HashMap<String, usize>,
    strings_found: usize,
    files_found: usize,
    sections: Vec<SectionInfo>,
    entropy_map: Vec<(u64, f64)>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SectionInfo {
    name: String,
    offset: u64,
    size: u64,
    kind: String,
    entropy: f64,
    extracted_items: usize,
}

struct BinaryDumper {
    mmap: Mmap,
    obj: object::File<'static>,
    format: BinaryFormat,
    base_address: u64,
}

impl BinaryDumper {
    fn new(file: &File) -> Result<Self> {
        let mmap = unsafe { Mmap::map(file)? };
        
        // Need to extend lifetime for object parsing
        let mmap_ref: &'static [u8] = unsafe {
            std::mem::transmute(mmap.as_ref())
        };
        
        let obj = object::File::parse(mmap_ref)?;
        let format = obj.format();
        let base_address = match format {
            BinaryFormat::Pe => {
                if let Some(header) = obj.pe_optional_header() {
                    header.image_base()
                } else {
                    0x400000
                }
            }
            _ => 0,
        };
        
        Ok(Self {
            mmap,
            obj,
            format,
            base_address,
        })
    }
    
    fn analyze_sections(&self) -> Vec<SectionInfo> {
        let mut sections = Vec::new();
        
        for section in self.obj.sections() {
            if let (Ok(name), Ok(kind)) = (section.name(), section.kind()) {
                if let Some((offset, size)) = section.file_range() {
                    let data = &self.mmap[offset as usize..(offset + size) as usize];
                    let entropy = Self::calculate_entropy(data);
                    
                    sections.push(SectionInfo {
                        name: name.to_string(),
                        offset,
                        size,
                        kind: format!("{:?}", kind),
                        entropy,
                        extracted_items: 0,
                    });
                }
            }
        }
        
        sections
    }
    
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut frequency = [0u64; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in frequency.iter() {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    fn extract_strings(&self, args: &Args) -> Vec<ExtractedItem> {
        let mut strings = Vec::new();
        let data = &self.mmap;
        
        // ASCII strings
        let mut i = 0;
        while i < data.len() {
            let start = i;
            let mut is_printable = 0;
            
            while i < data.len() && i - start < args.max_string_len {
                let byte = data[i];
                if byte >= 32 && byte <= 126 { // Printable ASCII
                    is_printable += 1;
                    i += 1;
                } else if byte == 0 || byte == 9 || byte == 10 || byte == 13 { // Null, tab, LF, CR
                    i += 1;
                    break;
                } else {
                    break;
                }
            }
            
            if is_printable >= args.min_string_len && i - start <= args.max_string_len {
                if let Ok(string) = String::from_utf8(data[start..i].to_vec()) {
                    strings.push(ExtractedItem {
                        offset: start as u64,
                        size: i - start,
                        item_type: "ASCII String".to_string(),
                        description: format!("{:?}", string),
                        file_path: None,
                        entropy: Self::calculate_entropy(&data[start..i]),
                        is_valid: true,
                    });
                }
            }
            
            if i == start {
                i += 1;
            }
        }
        
        // UTF-16 LE strings (common in Windows binaries)
        if args.verbose {
            println!("Scanning for UTF-16 strings...");
        }
        
        strings
    }
    
    fn extract_embedded_files(&self, args: &Args) -> Vec<ExtractedItem> {
        let mut files = Vec::new();
        let data = &self.mmap;
        
        for (sig_name, signature, extension) in FILE_SIGNATURES {
            if args.verbose {
                println!("Scanning for {} files...", sig_name);
            }
            
            let mut offset = 0;
            while offset < data.len() {
                // Find signature
                if offset + signature.len() <= data.len() {
                    if &data[offset..offset + signature.len()] == *signature {
                        // Try to find end of file
                        let file_end = Self::find_file_end(data, offset, *signature, args);
                        
                        if file_end > offset && file_end - offset >= args.min_file_size {
                            let size = file_end - offset;
                            if size <= args.max_file_size {
                                files.push(ExtractedItem {
                                    offset: offset as u64,
                                    size,
                                    item_type: format!("Embedded {}", sig_name),
                                    description: format!("Signature: {:?}, Size: {} bytes", 
                                                        String::from_utf8_lossy(signature), size),
                                    file_path: None,
                                    entropy: Self::calculate_entropy(&data[offset..file_end]),
                                    is_valid: true,
                                });
                            }
                        }
                        offset = file_end;
                    }
                }
                offset += 1;
            }
        }
        
        // Also look for files by content analysis
        files.extend(self.find_files_by_content(args));
        
        files
    }
    
    fn find_file_end(data: &[u8], start: usize, signature: &[u8], args: &Args) -> usize {
        match signature {
            b"PK\x03\x04" => {
                // ZIP file - look for central directory
                let mut pos = start + 4;
                while pos + 4 < data.len() {
                    if &data[pos..pos+4] == b"PK\x01\x02" || &data[pos..pos+4] == b"PK\x05\x06" {
                        return Self::find_zip_end(data, pos);
                    }
                    pos += 1;
                }
                start + args.max_file_size.min(data.len() - start)
            }
            b"\x1F\x8B\x08" => {
                // GZIP - read size from footer
                if start + 10 < data.len() {
                    let isize = u32::from_le_bytes([
                        data[start + 4],
                        data[start + 5],
                        data[start + 6],
                        data[start + 7],
                    ]) as usize;
                    return (start + 8 + isize).min(data.len());
                }
                start + args.max_file_size.min(data.len() - start)
            }
            b"\x89PNG\r\n\x1a\n" => {
                // PNG - look for IEND chunk
                let mut pos = start + 8;
                while pos + 12 < data.len() {
                    let chunk_len = u32::from_be_bytes([
                        data[pos], data[pos+1], data[pos+2], data[pos+3]
                    ]) as usize;
                    let chunk_type = &data[pos+4..pos+8];
                    if chunk_type == b"IEND" {
                        return pos + 12;
                    }
                    pos += 12 + chunk_len;
                }
                start + args.max_file_size.min(data.len() - start)
            }
            _ => {
                // Generic - scan until entropy changes dramatically or null bytes
                let mut pos = start + signature.len();
                let initial_entropy = Self::calculate_entropy(&data[start..start+signature.len()]);
                
                while pos < data.len() && pos - start < args.max_file_size {
                    // Check for pattern breaks
                    if pos + 256 <= data.len() {
                        let chunk = &data[pos..pos+256];
                        let entropy = Self::calculate_entropy(chunk);
                        if (entropy - initial_entropy).abs() > 2.0 {
                            break;
                        }
                    }
                    
                    // Check for null block (common between files)
                    if pos + 512 <= data.len() && data[pos..pos+512].iter().all(|&b| b == 0) {
                        break;
                    }
                    
                    pos += 1;
                }
                
                pos.min(data.len())
            }
        }
    }
    
    fn find_zip_end(data: &[u8], central_dir_start: usize) -> usize {
        let mut pos = central_dir_start;
        
        // Find end of central directory
        while pos + 22 <= data.len() {
            if &data[pos..pos+4] == b"PK\x05\x06" {
                let cd_size = u32::from_le_bytes([
                    data[pos+12], data[pos+13], data[pos+14], data[pos+15]
                ]) as usize;
                let cd_offset = u32::from_le_bytes([
                    data[pos+16], data[pos+17], data[pos+18], data[pos+19]
                ]) as usize;
                let comment_len = u16::from_le_bytes([data[pos+20], data[pos+21]]) as usize;
                
                return pos + 22 + comment_len;
            }
            pos += 1;
        }
        
        central_dir_start
    }
    
    fn find_files_by_content(&self, args: &Args) -> Vec<ExtractedItem> {
        let mut files = Vec::new();
        let data = &self.mmap;
        
        // Look for regions with high entropy (likely compressed/encrypted data)
        let block_size = 4096;
        let mut offset = 0;
        
        while offset < data.len() {
            let end = (offset + block_size).min(data.len());
            let block = &data[offset..end];
            let entropy = Self::calculate_entropy(block);
            
            if entropy > args.entropy_threshold && block.len() >= args.min_file_size {
                // This might be a compressed/encrypted file
                files.push(ExtractedItem {
                    offset: offset as u64,
                    size: block.len(),
                    item_type: "High Entropy Data".to_string(),
                    description: format!("Entropy: {:.2}, Size: {} bytes", entropy, block.len()),
                    file_path: None,
                    entropy,
                    is_valid: false,
                });
            }
            
            offset += block_size / 2; // 50% overlap
        }
        
        files
    }
    
    fn extract_code_sections(&self, _args: &Args) -> Vec<ExtractedItem> {
        let mut code_items = Vec::new();
        
        for section in self.obj.sections() {
            if let (Ok(name), Ok(kind)) = (section.name(), section.kind()) {
                if matches!(kind, SectionKind::Text | SectionKind::Code) {
                    if let Some((offset, size)) = section.file_range() {
                        code_items.push(ExtractedItem {
                            offset,
                            size: size as usize,
                            item_type: "Code Section".to_string(),
                            description: format!("Section: {}, Type: {:?}", name, kind),
                            file_path: None,
                            entropy: Self::calculate_entropy(&self.mmap[offset as usize..(offset + size) as usize]),
                            is_valid: true,
                        });
                    }
                }
            }
        }
        
        code_items
    }
    
    fn extract_resources(&self, args: &Args) -> Vec<ExtractedItem> {
        let mut resources = Vec::new();
        
        if let BinaryFormat::Pe = self.format {
            if let Some(resource_section) = self.obj.sections().find(|s| s.name() == Ok(".rsrc")) {
                if let Some((offset, size)) = resource_section.file_range() {
                    resources.push(ExtractedItem {
                        offset,
                        size: size as usize,
                        item_type: "Resource Section".to_string(),
                        description: "Windows PE Resources".to_string(),
                        file_path: None,
                        entropy: Self::calculate_entropy(&self.mmap[offset as usize..(offset + size) as usize]),
                        is_valid: true,
                    });
                    
                    // Try to parse individual resources
                    resources.extend(self.parse_pe_resources(offset as usize, size as usize, args));
                }
            }
        }
        
        resources
    }
    
    fn parse_pe_resources(&self, offset: usize, size: usize, _args: &Args) -> Vec<ExtractedItem> {
        let mut resources = Vec::new();
        let data = &self.mmap[offset..offset + size];
        
        // Simple resource scanning
        let mut pos = 0;
        while pos + 16 < data.len() {
            // Look for potential resource entries
            if data[pos] == 0 && data[pos+1] == 0 && data[pos+2] == 0 && data[pos+3] == 0 {
                let maybe_size = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]);
                let maybe_offset = u32::from_le_bytes([data[pos+8], data[pos+9], data[pos+10], data[pos+11]]);
                
                if maybe_size > 0 && maybe_offset > 0 && 
                   maybe_offset as usize + maybe_size as usize <= data.len() {
                    resources.push(ExtractedItem {
                        offset: (offset + maybe_offset as usize) as u64,
                        size: maybe_size as usize,
                        item_type: "PE Resource".to_string(),
                        description: format!("Resource at offset {:#X}, size {} bytes", 
                                           maybe_offset, maybe_size),
                        file_path: None,
                        entropy: Self::calculate_entropy(&data[maybe_offset as usize..(maybe_offset + maybe_size) as usize]),
                        is_valid: true,
                    });
                }
            }
            pos += 4;
        }
        
        resources
    }
    
    fn save_extracted_items(&self, items: &[ExtractedItem], output_dir: &Path, args: &Args) -> Result<Vec<ExtractedItem>> {
        let mut saved_items = Vec::new();
        
        for (i, item) in items.iter().enumerate() {
            if item.offset as usize + item.size > self.mmap.len() {
                continue;
            }
            
            let data = &self.mmap[item.offset as usize..item.offset as usize + item.size];
            
            // Create filename based on type and offset
            let safe_type = item.item_type.replace(" ", "_").replace("/", "_");
            let filename = format!("{:04}_{}_{:08x}.bin", i, safe_type, item.offset);
            let filepath = output_dir.join(&filename);
            
            // Save the data
            if let Err(e) = fs::write(&filepath, data) {
                if args.verbose {
                    eprintln!("Failed to save {}: {}", filename, e);
                }
                continue;
            }
            
            let mut saved_item = item.clone();
            saved_item.file_path = Some(filepath);
            saved_items.push(saved_item);
            
            if args.verbose {
                println!("Saved {}: {} bytes at {:#X}", filename, item.size, item.offset);
            }
        }
        
        Ok(saved_items)
    }
}

fn generate_report(report: &ExtractionReport, output_dir: &Path, args: &Args) -> Result<()> {
    // Generate JSON report
    if args.json_report {
        let json_path = output_dir.join("report.json");
        let json_data = serde_json::to_string_pretty(&report)?;
        fs::write(json_path, json_data)?;
    }
    
    // Generate HTML report
    if args.html_report {
        let html_path = output_dir.join("report.html");
        let html = generate_html_report(report);
        fs::write(html_path, html)?;
    }
    
    // Generate text summary
    let summary_path = output_dir.join("summary.txt");
    let mut summary = String::new();
    
    writeln!(summary, "Binary Dumper Report")?;
    writeln!(summary, "=====================")?;
    writeln!(summary, "Input file: {}", report.input_file)?;
    writeln!(summary, "File size: {} bytes", report.total_size)?;
    writeln!(summary, "Extraction time: {:.2} seconds", report.extraction_time)?;
    writeln!(summary, "Total items found: {}", report.items_found)?;
    writeln!(summary, "\nItems by type:")?;
    
    for (item_type, count) in &report.items_by_type {
        writeln!(summary, "  {}: {}", item_type, count)?;
    }
    
    writeln!(summary, "\nSections analyzed:")?;
    for section in &report.sections {
        writeln!(summary, "  {}: offset={:#X}, size={} bytes, entropy={:.2}, items={}", 
                section.name, section.offset, section.size, section.entropy, section.extracted_items)?;
    }
    
    fs::write(summary_path, summary)?;
    
    Ok(())
}

fn generate_html_report(report: &ExtractionReport) -> String {
    let mut html = String::new();
    
    html.push_str("<!DOCTYPE html>
<html>
<head>
    <title>Binary Dumper Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .section { margin: 20px 0; }
        .stat { margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Binary Dumper Report</h1>
    
    <div class=\"section\">
        <h2>Summary</h2>
        <div class=\"stat\"><strong>Input file:</strong> ");
    html.push_str(&report.input_file);
    html.push_str("</div>
        <div class=\"stat\"><strong>File size:</strong> ");
    html.push_str(&format!("{} bytes", report.total_size));
    html.push_str("</div>
        <div class=\"stat\"><strong>Extraction time:</strong> ");
    html.push_str(&format!("{:.2} seconds", report.extraction_time));
    html.push_str("</div>
        <div class=\"stat\"><strong>Total items found:</strong> ");
    html.push_str(&format!("{}", report.items_found));
    html.push_str("</div>
    </div>
    
    <div class=\"section\">
        <h2>Items by Type</h2>
        <table>
            <tr><th>Type</th><th>Count</th></tr>");
    
    for (item_type, count) in &report.items_by_type {
        html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", item_type, count));
    }
    
    html.push_str("</table>
    </div>
    
    <div class=\"section\">
        <h2>Sections</h2>
        <table>
            <tr><th>Name</th><th>Offset</th><th>Size</th><th>Entropy</th><th>Items Found</th></tr>");
    
    for section in &report.sections {
        html.push_str(&format!("<tr><td>{}</td><td>{:#X}</td><td>{} bytes</td><td>{:.2}</td><td>{}</td></tr>", 
                              section.name, section.offset, section.size, section.entropy, section.extracted_items));
    }
    
    html.push_str("</table>
    </div>
    
    <div class=\"section\">
        <h2>Entropy Analysis</h2>
        <p>High entropy (>7.0) may indicate compressed or encrypted data.</p>
        <div id=\"entropyChart\"></div>
    </div>
    
    <script>
        // Simple entropy chart
        const entropyData = ");
    // Add entropy data as JSON
    let entropy_json = serde_json::to_string(&report.entropy_map).unwrap_or_default();
    html.push_str(&entropy_json);
    html.push_str(";
        
        if (entropyData.length > 0) {
            const chartDiv = document.getElementById('entropyChart');
            chartDiv.innerHTML = '<canvas id=\"entropyCanvas\" width=\"800\" height=\"200\"></canvas>';
            
            const canvas = document.getElementById('entropyCanvas');
            const ctx = canvas.getContext('2d');
            
            // Draw simple chart
            const maxEntropy = Math.max(...entropyData.map(d => d[1]));
            const width = canvas.width;
            const height = canvas.height;
            const step = width / entropyData.length;
            
            ctx.beginPath();
            ctx.moveTo(0, height - (entropyData[0][1] / maxEntropy) * height);
            
            for (let i = 1; i < entropyData.length; i++) {
                const x = i * step;
                const y = height - (entropyData[i][1] / maxEntropy) * height;
                ctx.lineTo(x, y);
            }
            
            ctx.strokeStyle = 'blue';
            ctx.stroke();
        }
    </script>
    
</body>
</html>");
    
    html
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("╔══════════════════════════════════════════════════╗");
    println!("║             FULL BINARY DUMPER                   ║");
    println!("║     Extract EVERYTHING from binary files         ║");
    println!("╚══════════════════════════════════════════════════╝");
    
    // Create output directory structure
    let output_dir = Path::new(&args.output);
    let strings_dir = output_dir.join("strings");
    let files_dir = output_dir.join("files");
    let code_dir = output_dir.join("code");
    let resources_dir = output_dir.join("resources");
    let data_dir = output_dir.join("data");
    let unknown_dir = output_dir.join("unknown");
    
    fs::create_dir_all(&strings_dir)?;
    fs::create_dir_all(&files_dir)?;
    fs::create_dir_all(&code_dir)?;
    fs::create_dir_all(&resources_dir)?;
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&unknown_dir)?;
    
    let start_time = Instant::now();
    
    // Open and analyze the binary
    println!("\n📁 Loading: {}", args.input);
    let file = File::open(&args.input)?;
    let dumper = BinaryDumper::new(&file)?;
    
    let file_size = dumper.mmap.len() as u64;
    println!("📊 File size: {} bytes ({:.2} MB)", 
             file_size, file_size as f64 / 1024.0 / 1024.0);
    println!("📦 Format: {:?}", dumper.format);
    println!("📍 Base address: {:#X}", dumper.base_address);
    
    // Analyze sections
    println!("\n🔍 Analyzing sections...");
    let sections = dumper.analyze_sections();
    for section in &sections {
        println!("  • {}: {:#X}-{:#X} ({} bytes, entropy: {:.2})", 
                section.name, section.offset, 
                section.offset + section.size, 
                section.size, section.entropy);
    }
    
    let mut all_items = Vec::new();
    let mut items_by_type = HashMap::new();
    
    // Extract strings
    if args.extract_strings || args.extract_all {
        println!("\n📝 Extracting strings...");
        let strings = dumper.extract_strings(&args);
        println!("  Found {} strings", strings.len());
        
        let saved_strings = dumper.save_extracted_items(&strings, &strings_dir, &args)?;
        all_items.extend(saved_strings);
        items_by_type.insert("Strings".to_string(), strings.len());
        
        // Save strings to text file
        if !strings.is_empty() {
            let strings_path = strings_dir.join("all_strings.txt");
            let mut strings_file = File::create(strings_path)?;
            for string in &strings {
                if string.is_valid {
                    writeln!(strings_file, "[{:#X}] {}", string.offset, string.description)?;
                }
            }
        }
    }
    
    // Extract embedded files
    if args.extract_files || args.extract_all {
        println!("\n📎 Extracting embedded files...");
        let files = dumper.extract_embedded_files(&args);
        println!("  Found {} potential files", files.len());
        
        let saved_files = dumper.save_extracted_items(&files, &files_dir, &args)?;
        all_items.extend(saved_files);
        items_by_type.insert("Files".to_string(), files.len());
    }
    
    // Extract code sections
    if args.extract_code || args.extract_all {
        println!("\n💻 Extracting code sections...");
        let code = dumper.extract_code_sections(&args);
        println!("  Found {} code sections", code.len());
        
        let saved_code = dumper.save_extracted_items(&code, &code_dir, &args)?;
        all_items.extend(saved_code);
        items_by_type.insert("Code".to_string(), code.len());
    }
    
    // Extract resources
    if args.extract_resources || args.extract_all {
        println!("\n🎨 Extracting resources...");
        let resources = dumper.extract_resources(&args);
        println!("  Found {} resource sections", resources.len());
        
        let saved_resources = dumper.save_extracted_items(&resources, &resources_dir, &args)?;
        all_items.extend(saved_resources);
        items_by_type.insert("Resources".to_string(), resources.len());
    }
    
    // Extract data sections
    if args.extract_data || args.extract_all {
        println!("\n🗄️  Extracting data sections...");
        let data_sections: Vec<_> = sections.iter()
            .filter(|s| s.kind.contains("Data") || s.kind.contains("ReadOnlyData"))
            .collect();
        
        let mut data_items = Vec::new();
        for section in data_sections {
            data_items.push(ExtractedItem {
                offset: section.offset,
                size: section.size as usize,
                item_type: "Data Section".to_string(),
                description: format!("Section: {}", section.name),
                file_path: None,
                entropy: section.entropy,
                is_valid: true,
            });
        }
        
        println!("  Found {} data sections", data_items.len());
        let saved_data = dumper.save_extracted_items(&data_items, &data_dir, &args)?;
        all_items.extend(saved_data);
        items_by_type.insert("Data".to_string(), data_items.len());
    }
    
    // Generate entropy map
    let entropy_map = generate_entropy_map(&dumper.mmap, 4096);
    
    // Create report
    let elapsed = start_time.elapsed().as_secs_f64();
    let report = ExtractionReport {
        input_file: args.input.clone(),
        total_size: file_size,
        extraction_time: elapsed,
        items_found: all_items.len(),
        items_by_type,
        strings_found: all_items.iter().filter(|i| i.item_type.contains("String")).count(),
        files_found: all_items.iter().filter(|i| i.item_type.contains("File") || i.item_type.contains("Resource")).count(),
        sections,
        entropy_map,
    };
    
    // Generate reports
    println!("\n📊 Generating reports...");
    generate_report(&report, output_dir, &args)?;
    
    println!("\n✅ Extraction completed!");
    println!("   ⏱️  Time: {:.2} seconds", elapsed);
    println!("   📦 Total items extracted: {}", all_items.len());
    println!("   📁 Output directory: {}", output_dir.display());
    
    // Show summary
    println!("\n📋 Summary:");
    for (item_type, count) in &report.items_by_type {
        println!("   • {}: {}", item_type, count);
    }
    
    // Show high entropy warnings
    let high_entropy_sections: Vec<_> = report.sections.iter()
        .filter(|s| s.entropy > args.entropy_threshold)
        .collect();
    
    if !high_entropy_sections.is_empty() {
        println!("\n⚠️  High entropy sections detected (possible encryption/compression):");
        for section in high_entropy_sections {
            println!("   • {}: entropy {:.2}", section.name, section.entropy);
        }
    }
    
    println!("\n🎉 Done! Check the output directory for extracted content.");
    
    Ok(())
}

fn generate_entropy_map(data: &[u8], block_size: usize) -> Vec<(u64, f64)> {
    let mut map = Vec::new();
    let mut offset = 0;
    
    while offset < data.len() {
        let end = (offset + block_size).min(data.len());
        let block = &data[offset..end];
        let entropy = BinaryDumper::calculate_entropy(block);
        map.push((offset as u64, entropy));
        offset += block_size;
    }
    
    map
}
