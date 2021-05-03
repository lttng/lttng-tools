<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <!-- Callouts -->
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

    <!-- Links -->
    <xsl:template match="*[local-name() = 'ulink']">
        <xsl:apply-templates/><xsl:text> &lt;</xsl:text><xsl:value-of select="@url"/><xsl:text>&gt;</xsl:text>
    </xsl:template>
    <xsl:template match="*[local-name() = 'link']">
        <xsl:text>\fI</xsl:text><xsl:apply-templates/><xsl:text>\fR</xsl:text>
    </xsl:template>

    <!-- Literal -->
    <xsl:template match="*[local-name() = 'literal']">
        <xsl:text>\fB</xsl:text>
        <xsl:value-of select="." />
        <xsl:text>\fR</xsl:text>
    </xsl:template>

    <!--
        Make admonitions look like this:

            Some paragraph.

            Note
                Sit sed culpa elit dolore esse irure dolor amet magna
                veniam elit ut.

                Duis adipisicing magna quis in in in reprehenderit
                proident minim cupidatat dolore sit minim deserunt duis dolore ex ea.

            Next paragraph.

        instead of:

            Some paragraph.

                Note
                Sit sed culpa elit dolore esse irure dolor amet magna
                veniam elit ut.

                Duis adipisicing magna quis in in in reprehenderit
                proident minim cupidatat dolore sit minim deserunt duis
                dolore ex ea.

            Next paragraph.

        This looks better when, for example, you put a note immediately
        after a list:

        Ambiguous:
            •   Some list item.

            •   Some other list item.

                Note
                Does this note apply to the last list item or to the
                previous block?

        Clear:
            •   Some list item.

            •   Some other list item.

            Note
                This note applies to the previous block.
    -->
    <xsl:template match="caution|important|note|tip|warning">
        <xsl:call-template name="roff-if-start">
            <xsl:with-param name="condition">n</xsl:with-param>
        </xsl:call-template>
        <xsl:text>.sp&#10;</xsl:text>
        <xsl:call-template name="roff-if-end"/>
        <xsl:if test="not($man.output.better.ps.enabled = 0)">
            <xsl:text>.BM yellow&#10;</xsl:text>
        </xsl:if>
        <xsl:call-template name="pinch.together"/>
        <xsl:text>.ps +1&#10;</xsl:text>
        <xsl:call-template name="make.bold.title"/>
        <xsl:text>.ps -1&#10;</xsl:text>
        <xsl:text>.br&#10;</xsl:text>
        <xsl:text>.RS 4&#10;</xsl:text>
        <xsl:apply-templates/>
        <xsl:text>.sp .5v&#10;</xsl:text>
        <xsl:if test="not($man.output.better.ps.enabled = 0)">
            <xsl:text>.EM yellow&#10;</xsl:text>
        </xsl:if>
        <xsl:text>.RE&#10;</xsl:text>
    </xsl:template>

    <!-- Disable end notes -->
    <xsl:param name="man.endnotes.are.numbered">0</xsl:param>

    <!-- Disable hyphenation, except for URLs -->
    <xsl:param name="man.hyphenate">0</xsl:param>
</xsl:stylesheet>
