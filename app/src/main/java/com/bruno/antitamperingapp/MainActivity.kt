package com.bruno.antitamperingapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bruno.antitamperingapp.detection.DetectionCategory
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.Evidence
import com.bruno.antitamperingapp.detection.TamperStatus
import com.bruno.antitamperingapp.detection.TamperVerdict
import com.bruno.antitamperingapp.ui.theme.AntiTamperingAppTheme

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AntiTamperingAppTheme {
                val state by viewModel.uiState.collectAsState()
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    DashboardScreen(
                        state = state,
                        onScanClick = { viewModel.runScan() },
                        modifier = Modifier.padding(innerPadding),
                    )
                }
            }
        }
    }
}

@Composable
private fun DashboardScreen(
    state: ScanState,
    onScanClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(
                text = "Environment Scanner",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Runtime anomaly detection module",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
        }

        item {
            when (state) {
                is ScanState.Idle -> {
                    Button(
                        onClick = onScanClick,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Run Security Scan")
                    }
                }
                is ScanState.Scanning -> {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        CircularProgressIndicator()
                        Spacer(Modifier.height(8.dp))
                        Text("Scanning environment...", style = MaterialTheme.typography.bodyMedium)
                    }
                }
                is ScanState.Complete -> {
                    VerdictHeader(state.verdict)
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = onScanClick,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Re-scan")
                    }
                }
            }
        }

        if (state is ScanState.Complete) {
            val verdict = state.verdict

            items(verdict.results.entries.toList()) { (category, result) ->
                CategoryCard(category, result)
            }

            if (verdict.errors.isNotEmpty()) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                        ),
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                "Errors (${verdict.errors.size})",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            verdict.errors.forEach { error ->
                                Text(
                                    text = error.toString(),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                            }
                        }
                    }
                }
            }

            item {
                Text(
                    text = "Scan completed in ${verdict.durationMs}ms",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun VerdictHeader(verdict: TamperVerdict) {
    val statusColor = when (verdict.status) {
        TamperStatus.SECURE -> Color(0xFF4CAF50)
        TamperStatus.WARNING -> Color(0xFFFF9800)
        TamperStatus.TAMPERED -> Color(0xFFF44336)
    }
    val animatedColor by animateColorAsState(statusColor, label = "statusColor")
    val animatedScore by animateFloatAsState(verdict.overallScore, label = "score")

    Card(
        colors = CardDefaults.cardColors(containerColor = animatedColor.copy(alpha = 0.12f)),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .size(16.dp)
                    .clip(CircleShape)
                    .background(animatedColor),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = verdict.status.displayName,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = animatedColor,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Tampering likelihood: ${(animatedScore * 100).toInt()}%",
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { animatedScore },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .clip(RoundedCornerShape(4.dp)),
                color = animatedColor,
                trackColor = animatedColor.copy(alpha = 0.2f),
            )
        }
    }
}

@Composable
private fun CategoryCard(category: DetectionCategory, result: DetectionResult) {
    val suspicious = result.evidence.filter { it.suspicious }
    val clean = result.evidence.filter { !it.suspicious }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = category.displayName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                val statusText = if (result.detected) "DETECTED" else "CLEAN"
                val statusColor = if (result.detected) Color(0xFFF44336) else Color(0xFF4CAF50)
                Text(
                    text = statusText,
                    color = statusColor,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                )
            }

            Text(
                text = "Tampering likelihood: ${(result.confidence * 100).toInt()}% | " +
                    "Evidence: ${suspicious.size} suspicious, ${clean.size} clean",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
            )

            if (suspicious.isNotEmpty()) {
                Text(
                    text = "Suspicious signals:",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFFF44336),
                    modifier = Modifier.padding(bottom = 4.dp),
                )
                suspicious.forEach { evidence ->
                    EvidenceRow(evidence)
                }
            }

            if (clean.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Clean signals:",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF4CAF50),
                    modifier = Modifier.padding(bottom = 4.dp),
                )
                clean.forEach { evidence ->
                    EvidenceRow(evidence)
                }
            }
        }
    }
}

@Composable
private fun EvidenceRow(evidence: Evidence) {
    val dotColor = if (evidence.suspicious) Color(0xFFF44336) else Color(0xFF4CAF50)
    Column(modifier = Modifier.padding(start = 8.dp, bottom = 6.dp)) {
        Row(verticalAlignment = Alignment.Top) {
            Box(
                modifier = Modifier
                    .padding(top = 6.dp, end = 6.dp)
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(dotColor),
            )
            Column {
                Text(
                    text = evidence.description,
                    style = MaterialTheme.typography.bodySmall,
                )
                val rawValue = evidence.rawValue
                if (rawValue != null) {
                    Text(
                        text = rawValue,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp,
                    )
                }
            }
        }
    }
}
