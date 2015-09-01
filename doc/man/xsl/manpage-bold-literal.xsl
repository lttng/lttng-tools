<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:template match="literal">
        <xsl:text>\fB</xsl:text>
        <xsl:value-of select="." />
        <xsl:text>\fR</xsl:text>
    </xsl:template>
</xsl:stylesheet>
