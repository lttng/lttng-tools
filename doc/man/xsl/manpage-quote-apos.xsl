<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:template name="escape.apostrophe">
        <xsl:param name="content"/>
        <xsl:call-template name="string.subst">
            <xsl:with-param name="string" select="$content"/>
            <xsl:with-param name="target">'</xsl:with-param>
            <xsl:with-param name="replacement">\(aq</xsl:with-param>
        </xsl:call-template>
    </xsl:template>
</xsl:stylesheet>
