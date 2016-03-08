<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:import href="manpage-base.xsl" />
    <xsl:import href="manpage-bold-literal.xsl" />
    <xsl:import href="manpage-ulinks.xsl" />

    <!-- disable end notes -->
    <xsl:param name="man.endnotes.are.numbered">0</xsl:param>
</xsl:stylesheet>
