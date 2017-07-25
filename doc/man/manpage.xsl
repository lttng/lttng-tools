<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <!-- callouts -->
    <xsl:template match="*[local-name() = 'co']">
        <xsl:value-of select="concat('\','fB(',substring-after(@id,'-'),')','\','fR')"/>
    </xsl:template>
    <xsl:template match="*[local-name() = 'calloutlist']">
        <xsl:value-of select="."/>
        <xsl:text>sp&#10;</xsl:text>
        <xsl:apply-templates/>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>
    <xsl:template match="*[local-name() = 'callout']">
        <xsl:value-of select="concat('\','fB',substring-after(@arearefs,'-'),'. ','\','fR')"/>
        <xsl:apply-templates/>
        <xsl:value-of select="."/>
        <xsl:text>br&#10;</xsl:text>
    </xsl:template>

    <!-- links -->
    <xsl:template match="*[local-name() = 'ulink']">
        <xsl:apply-templates/><xsl:text> &lt;</xsl:text><xsl:value-of select="@url"/><xsl:text>&gt;</xsl:text>
    </xsl:template>
    <xsl:template match="*[local-name() = 'link']">
        <xsl:text>\fI</xsl:text><xsl:apply-templates/><xsl:text>\fR</xsl:text>
    </xsl:template>

    <!-- literal -->
    <xsl:template match="*[local-name() = 'literal']">
        <xsl:text>\fB</xsl:text>
        <xsl:value-of select="." />
        <xsl:text>\fR</xsl:text>
    </xsl:template>

    <!-- disable end notes -->
    <xsl:param name="man.endnotes.are.numbered">0</xsl:param>
</xsl:stylesheet>
