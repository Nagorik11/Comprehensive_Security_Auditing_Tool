#!/bin/bash
CAPTURE="${1:-captura.pcap}"
OUTPUT="${2:-informe_red}"
LOCAL_IP="${3:-192.168.1.4}"

echo "# 📊 Informe de Tráfico - $CAPTURE" > ${OUTPUT}.md
echo "**Generado:** $(date)" >> ${OUTPUT}.md
echo "**IP Local:** $LOCAL_IP" >> ${OUTPUT}.md
echo "" >> ${OUTPUT}.md

## 📈 Resumen
echo "## 📈 Resumen General" >> ${OUTPUT}.md
TOTAL=$(tshark -r "$CAPTURE" -Y "ip.addr==$LOCAL_IP" 2>/dev/null | wc -l)
DURACION=$(tshark -r "$CAPTURE" -q -z io,stat,0 2>/dev/null | grep "Duration:" | awk '{print $2}')
echo "- **Paquetes capturados:** $TOTAL" >> ${OUTPUT}.md
echo "- **Duración:** $DURACION segundos" >> ${OUTPUT}.md
echo "" >> ${OUTPUT}.md

## 🌐 Protocolos
echo "## 🌐 Protocolos Detectados" >> ${OUTPUT}.md
tshark -r "$CAPTURE" -q -z protocol,tree 2>/dev/null | head -20 >> ${OUTPUT}.md
echo "" >> ${OUTPUT}.md

## 💬 Conversaciones UDP
echo "## 💬 Top Conversaciones UDP" >> ${OUTPUT}.md
tshark -r "$CAPTURE" -q -z conv,udp 2>/dev/null | head -15 >> ${OUTPUT}.md
echo "" >> ${OUTPUT}.md

## 📦 Exportar datos normalizados
echo "## 📁 Datos Exportados" >> ${OUTPUT}.md
tshark -r "$CAPTURE" \
  -Y "ip.addr==$LOCAL_IP" \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e frame.len \
  -E header=y -E separator=, \
  2>/dev/null > "${OUTPUT}_datos.csv"
echo "- ✅ Datos normalizados: \`${OUTPUT}_datos.csv\`" >> ${OUTPUT}.md

echo ""
echo "✅ Informe generado: ${OUTPUT}.md"
echo "📊 CSV exportado: ${OUTPUT}_datos.csv"