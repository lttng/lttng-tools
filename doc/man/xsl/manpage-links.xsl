<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:template match="ulink">
        <xsl:apply-templates/><xsl:text> &lt;</xsl:text><xsl:value-of select="@url"/><xsl:text>&gt;</xsl:text>
    </xsl:template>
    <xsl:template match="link">
        <xsl:text>\fI</xsl:text><xsl:apply-templates/><xsl:text>\fR</xsl:text>
    </xsl:template>
</xsl:stylesheet>
