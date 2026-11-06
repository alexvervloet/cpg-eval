// Dump method line ranges and baseline detector findings from one CPG.
//
//   joern --script joern/extract.sc --param cpgFile=out/cpg.bin --param outDir=out
//
// Writes outDir/methods.json and outDir/findings.json. Filenames are as the
// CPG stores them, relative to the directory given to joern-parse.

import io.shiftleft.codepropertygraph.generated.nodes.{Call, Expression, Method}

// Size or length argument (1-based) for calls that copy a bounded amount.
val sizedCalls = Map(
  "memcpy" -> 3, "memmove" -> 3, "strncpy" -> 3, "strncat" -> 3,
  "snprintf" -> 2, "vsnprintf" -> 2,
)
// Calls with no bound at all.
val unboundedCalls = Set("strcpy", "strcat", "sprintf", "vsprintf", "gets")

val comparisons = Set(
  "<operator>.lessThan", "<operator>.lessEqualsThan",
  "<operator>.greaterThan", "<operator>.greaterEqualsThan",
)

def isConstant(e: Expression): Boolean =
  e.ast.isIdentifier.isEmpty && e.ast.isCall.nameNot("<operator>.*").isEmpty

// Variant 1: risky copy with a size that isn't a compile-time constant.
def riskyCopy(m: Method): Iterator[Call] =
  m.call.filter { c =>
    unboundedCalls.contains(c.name) ||
      sizedCalls.get(c.name).exists(i => c.argument.argumentIndex(i).headOption.exists(a => !isConstant(a)))
  }

// Variant 2: array or pointer index whose index variable never appears in a
// <, <=, > or >= comparison anywhere in the same method.
def uncheckedIndex(m: Method): Iterator[Call] = {
  val compared = m.call.filter(c => comparisons.contains(c.name)).ast.isIdentifier.name.toSet
  m.call.name("<operator>.indirectIndexAccess").filter { c =>
    val idx = c.argument.argumentIndex(2).ast.isIdentifier.name.toSet
    idx.nonEmpty && !idx.exists(compared.contains)
  }
}

val variants: Map[String, Method => Iterator[Call]] = Map(
  "risky_copy" -> riskyCopy,
  "unchecked_index" -> uncheckedIndex,
)

def esc(s: String): String = s.flatMap {
  case '"' => "\\\""
  case '\\' => "\\\\"
  case '\n' => "\\n"
  case '\r' => "\\r"
  case '\t' => "\\t"
  case c if c < ' ' => f"\\u${c.toInt}%04x"
  case c => c.toString
}

@main def exec(cpgFile: String, outDir: String): Unit = {
  importCpg(cpgFile)
  val methods = cpg.method.isExternal(false).nameNot("<global>")
    .filter(m => m.lineNumber.isDefined && m.lineNumberEnd.isDefined).l

  val methodRows = methods.map { m =>
    s"""{"file":"${esc(m.filename)}","name":"${esc(m.name)}","start":${m.lineNumber.get},"end":${m.lineNumberEnd.get}}"""
  }
  os.write.over(os.Path(outDir, os.pwd) / "methods.json", methodRows.mkString("[\n", ",\n", "\n]\n"))

  val findingRows = for {
    m <- methods
    (variant, rule) <- variants.toList
    c <- rule(m).l
  } yield s"""{"variant":"$variant","file":"${esc(m.filename)}","name":"${esc(m.name)}","line":${c.lineNumber.getOrElse(-1)},"code":"${esc(c.code.take(200))}"}"""
  os.write.over(os.Path(outDir, os.pwd) / "findings.json", findingRows.mkString("[\n", ",\n", "\n]\n"))

  println(s"${methods.size} methods, ${findingRows.size} findings -> $outDir")
}
